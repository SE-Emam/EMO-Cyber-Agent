"""Security mutations — POST-RC-013.

Mutations build adversarial fixture variants in memory: they rewrite a
scenario payload and optionally replace ground truth. They are refused
outright for production-sourced material, they never execute anything, and
they never touch Core state — a mutation only produces a new
:class:`EvaluationCase` for the benchmark to score.
"""

from __future__ import annotations

import copy
from enum import StrEnum
from typing import Any, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.evaluation.cases import EvaluationCase, EvaluationScenario
from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.ground_truth import GroundTruthRecord
from emo_cyber_agent.evaluation.spec import evaluation_digest

__all__ = [
    "MutationOperation",
    "SecurityMutationKind",
    "SecurityMutation",
    "apply_mutation",
    "MUTATION_KINDS",
]


class MutationOperation(StrEnum):
    REMOVE_KEY = "remove_key"
    SET_VALUE = "set_value"
    APPEND_TEXT = "append_text"
    REPLACE_TEXT = "replace_text"


class SecurityMutationKind(StrEnum):
    REMOVE_AUTH_CHECK = "remove_auth_check"
    POISON_MEMORY = "poison_memory"
    INJECT_TOOL_DESCRIPTION = "inject_tool_description"
    INJECT_PROMPT_INSTRUCTION = "inject_prompt_instruction"
    WEAKEN_VALIDATION = "weaken_validation"
    TAMPER_POLICY_GRANT = "tamper_policy_grant"
    EXPOSE_SECRET = "expose_secret"
    DISABLE_VERIFICATION = "disable_verification"
    FLATTEN_PROVENANCE = "flatten_provenance"
    REDIRECT_SCOPE = "redirect_scope"


MUTATION_KINDS: tuple[str, ...] = tuple(kind.value for kind in SecurityMutationKind)


class SecurityMutation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mutation_id: str = Field(default="", max_length=96)
    kind: SecurityMutationKind
    operation: MutationOperation
    target: str = Field(..., min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9_.\-\[\]]+$")
    value: Any = None
    ground_truth: tuple[GroundTruthRecord, ...] = Field(default_factory=tuple, max_length=64)
    source_system: str = Field(default="evaluation-lab", min_length=1, max_length=64)
    production: bool = False
    note: str = Field(default="", max_length=300)

    @property
    def stable_id(self) -> str:
        if self.mutation_id:
            return self.mutation_id
        digest = evaluation_digest(
            {
                "kind": self.kind.value,
                "operation": self.operation.value,
                "target": self.target,
                "value": self.value,
            }
        )
        return f"mut-{digest[:16]}"


def _split(target: str) -> list[str]:
    parts: list[str] = []
    for segment in str(target).split("."):
        while "[" in segment:
            head, _, rest = segment.partition("[")
            if head:
                parts.append(head)
            index, _, tail = rest.partition("]")
            parts.append(f"[{index}]")
            segment = tail
        if segment:
            parts.append(segment)
    return parts or [str(target)]


def _resolve(container: Any, parts: Sequence[str]) -> tuple[Any, Any, str]:
    """Returns (parent, current, last_key) without mutating."""
    current = container
    for index, part in enumerate(parts[:-1]):
        nxt = _step(current, part)
        if nxt is _MISSING:
            raise EvaluationError(
                EvaluationErrorCode.MUTATION_INVALID,
                f"mutation target not found at {'.'.join(parts[: index + 1])}",
            )
        current = nxt
    return current, _step(current, parts[-1], missing_ok=True), parts[-1]


_MISSING = object()


def _step(node: Any, part: str, *, missing_ok: bool = False) -> Any:
    if part.startswith("[") and part.endswith("]"):
        try:
            index = int(part[1:-1])
        except ValueError as exc:
            raise EvaluationError(
                EvaluationErrorCode.MUTATION_INVALID,
                f"list index required in {part}",
            ) from exc
        if isinstance(node, (list, tuple)) and 0 <= index < len(node):
            return node[index]
        if missing_ok:
            return _MISSING
        raise EvaluationError(EvaluationErrorCode.MUTATION_INVALID, f"list index out of range: {part}")
    if isinstance(node, dict):
        if part in node:
            return node[part]
        if missing_ok:
            return _MISSING
        raise EvaluationError(EvaluationErrorCode.MUTATION_INVALID, f"key not found: {part}")
    if missing_ok:
        return _MISSING
    raise EvaluationError(EvaluationErrorCode.MUTATION_INVALID, f"cannot descend into {type(node).__name__}")


def apply_mutation(case: EvaluationCase, mutation: SecurityMutation) -> EvaluationCase:
    if mutation.production or case.source.production:
        raise EvaluationError(
            EvaluationErrorCode.MUTATION_REFUSED,
            "mutations are refused for production-sourced material",
        )
    payload = copy.deepcopy(dict(case.scenario.payload))
    parts = _split(mutation.target)
    operation = mutation.operation

    if operation is MutationOperation.REMOVE_KEY:
        parent, current, key = _resolve(payload, parts)
        if current is _MISSING or not isinstance(parent, dict):
            raise EvaluationError(
                EvaluationErrorCode.MUTATION_INVALID,
                f"remove_key needs an existing mapping key: {mutation.target}",
            )
        del parent[key]
    elif operation is MutationOperation.SET_VALUE:
        parent, current, key = _resolve(payload, parts)
        if current is _MISSING and not isinstance(parent, dict):
            raise EvaluationError(
                EvaluationErrorCode.MUTATION_INVALID,
                f"set_value needs a mapping parent: {mutation.target}",
            )
        if isinstance(parent, dict):
            parent[key] = copy.deepcopy(mutation.value)
        else:
            raise EvaluationError(
                EvaluationErrorCode.MUTATION_INVALID,
                f"set_value on non-mapping parent: {mutation.target}",
            )
    elif operation in (MutationOperation.APPEND_TEXT, MutationOperation.REPLACE_TEXT):
        parent, current, key = _resolve(payload, parts)
        if current is _MISSING:
            raise EvaluationError(
                EvaluationErrorCode.MUTATION_INVALID,
                f"text mutation needs an existing value: {mutation.target}",
            )
        addition = "" if mutation.value is None else str(mutation.value)
        if operation is MutationOperation.APPEND_TEXT:
            replaced = f"{current}{addition}"
        else:
            replaced = addition
        if isinstance(parent, dict):
            parent[key] = replaced
        elif isinstance(parent, list) and key.startswith("["):
            parent[int(key[1:-1])] = replaced
        else:
            raise EvaluationError(
                EvaluationErrorCode.MUTATION_INVALID,
                f"cannot write text at {mutation.target}",
            )
    else:  # pragma: no cover - closed enum
        raise EvaluationError(
            EvaluationErrorCode.MUTATION_INVALID,
            f"unsupported mutation operation: {operation.value}",
        )

    digest = evaluation_digest({"case": case.case_id, "mutation": mutation.stable_id})
    suffix = f"mut-{digest[:10]}"
    mutated_id = f"{case.case_id[:80]}-{suffix}"
    ground_truth = mutation.ground_truth or case.ground_truth
    return EvaluationCase(
        case_id=mutated_id,
        title=f"{case.title} [{mutation.kind.value}]",
        track=case.track,
        taxonomy=case.taxonomy,
        stage=case.stage,
        visibility=case.visibility,
        split=case.split,
        tags=tuple(dict.fromkeys([*case.tags, "mutated", mutation.kind.value])),
        scenario=EvaluationScenario(kind=case.scenario.kind, payload=payload),
        section=case.section,
        ground_truth=tuple(ground_truth),
        source=case.source,
        notes=f"{case.notes} mutation={mutation.stable_id} {mutation.note}".strip()[:1000],
    )


def mutate_many(
    case: EvaluationCase,
    mutations: Iterable[SecurityMutation],
) -> tuple[EvaluationCase, ...]:
    result: list[EvaluationCase] = []
    for mutation in mutations:
        result.append(apply_mutation(case, mutation))
    return tuple(result)


def describe_mutations(case_ids: Sequence[str], mutations: Sequence[SecurityMutation]) -> Mapping[str, str]:
    pairs = {case_id: mutation.stable_id for case_id, mutation in zip(case_ids, mutations, strict=False)}
    return dict(sorted(pairs.items()))
