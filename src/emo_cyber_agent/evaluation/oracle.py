"""Oracles — POST-RC-013.

An oracle turns (case, system output, ground truth) into judgments. Three
built-in oracles cover the corpus:

- :class:`GroundTruthOracle` — the generic record comparator;
- :class:`RedactionOracle` — scans every serialized system output for
  credential-shaped material (security-relevant, always);
- :class:`AuthorityOracle` — compares the before/after authority snapshot
  and reports any drift as a security disagreement.

Judgments are pure data: no timestamps, no identifiers, no wall clock, so
two identical runs produce byte-identical judgment streams.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.evaluation.cases import EvaluationCase
from emo_cyber_agent.evaluation.ground_truth import GroundTruthRecord, judge_record, resolve_subject
from emo_cyber_agent.evaluation.spec import (
    AuthorityDiff,
    EvaluationObservation,
    EvaluationStage,
    GroundTruthKind,
    OracleVerdict,
    SECURITY_GROUND_TRUTH_KINDS,
    SECURITY_STAGES,
    evaluation_digest,
)
from emo_cyber_agent.evaluation.sut import SUTResult

__all__ = [
    "OracleJudgment",
    "OracleContext",
    "Oracle",
    "GroundTruthOracle",
    "RedactionOracle",
    "AuthorityOracle",
    "ParityOracle",
    "default_oracles",
    "DEFAULT_ORACLE_NAMES",
    "LEAK_PATTERNS",
    "find_leaks",
]

CHECK_GROUND_TRUTH = "ground_truth"
CHECK_REDACTION = "redaction"
CHECK_AUTHORITY = "authority"
CHECK_PARITY = "parity"

_LEAK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk_live_[0-9a-zA-Z]{8,}"),
    re.compile(r"sk_test_[0-9a-zA-Z]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[0-9a-zA-Z]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?:password|passwd|api_key|apikey|secret|token)\s*[=:]\s*['\"][^'\"]{6,}", re.IGNORECASE),
)
LEAK_PATTERNS: tuple[str, ...] = tuple(p.pattern for p in _LEAK_PATTERNS)


def find_leaks(text: str) -> tuple[str, ...]:
    return tuple(p.pattern for p in _LEAK_PATTERNS if p.search(text or ""))


class OracleJudgment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(..., min_length=1, max_length=96)
    oracle: str = Field(..., min_length=1, max_length=48)
    check: str = Field(..., min_length=1, max_length=48)
    stage: str = Field(..., min_length=1, max_length=64)
    track: str = Field(..., min_length=1, max_length=32)
    verdict: OracleVerdict
    gt_kind: str = Field(default="", max_length=48)
    gt_record_id: str = Field(default="", max_length=96)
    subject: str = Field(default="", max_length=256)
    reason_codes: tuple[str, ...] = ()
    security_relevant: bool = False
    disagreement: bool = False
    detail: str = Field(default="", max_length=300)

    @property
    def identity_digest(self) -> str:
        return evaluation_digest(
            {
                "case_id": self.case_id,
                "oracle": self.oracle,
                "check": self.check,
                "stage": self.stage,
                "track": self.track,
                "verdict": self.verdict.value,
                "gt_kind": self.gt_kind,
                "gt_record_id": self.gt_record_id,
                "subject": self.subject,
                "reason_codes": list(self.reason_codes),
                "security_relevant": self.security_relevant,
                "disagreement": self.disagreement,
            }
        )


class OracleContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case: EvaluationCase
    result: SUTResult
    observations: tuple[EvaluationObservation, ...] = ()
    authority_diff: AuthorityDiff | None = None


class Oracle(ABC):
    name: str = "oracle"

    @abstractmethod
    def evaluate(self, context: OracleContext) -> list[OracleJudgment]: ...


def _payloads(context: OracleContext, *, stage: str = "") -> list[Mapping[str, Any]]:
    if not stage:
        return [obs.payload for obs in context.observations]
    wanted = EvaluationStage(stage)
    return [obs.payload for obs in context.observations if obs.stage is wanted]


def _verdict_on_error(context: OracleContext, check: str, **extra: Any) -> OracleJudgment:
    case = context.case
    return OracleJudgment(
        case_id=case.case_id,
        oracle="ground_truth",
        check=check,
        stage=case.stage.value,
        track=case.track.value,
        verdict=OracleVerdict.ERROR,
        reason_codes=("sut-error", context.result.error_code or "unknown") ,
        security_relevant=case.stage.value in SECURITY_STAGES,
        disagreement=True,
        detail=context.result.error_message[:200],
        **extra,
    )


class GroundTruthOracle(Oracle):
    name = "ground_truth"

    def evaluate(self, context: OracleContext) -> list[OracleJudgment]:
        case = context.case
        judgments: list[OracleJudgment] = []
        if not context.result.ok:
            for record in case.ground_truth:
                judgments.append(
                    _verdict_on_error(
                        context,
                        CHECK_GROUND_TRUTH,
                        gt_kind=record.kind.value,
                        gt_record_id=record.record_id,
                        subject=record.subject,
                    )
                )
            return judgments
        for record in case.ground_truth:
            stage = record.stage or ""
            payloads = _payloads(context, stage=stage)
            verdict = judge_record(record, payloads)
            security = record.kind.value in SECURITY_GROUND_TRUTH_KINDS or case.stage.value in SECURITY_STAGES
            judgments.append(
                OracleJudgment(
                    case_id=case.case_id,
                    oracle=self.name,
                    check=CHECK_GROUND_TRUTH,
                    stage=case.stage.value,
                    track=case.track.value,
                    verdict=verdict,
                    gt_kind=record.kind.value,
                    gt_record_id=record.record_id,
                    subject=record.subject,
                    reason_codes=_reasons(verdict),
                    security_relevant=security,
                    disagreement=verdict in (OracleVerdict.REFUTED, OracleVerdict.ERROR),
                    detail=_detail(verdict, record),
                )
            )
        return judgments


def _reasons(verdict: OracleVerdict) -> tuple[str, ...]:
    if verdict is OracleVerdict.SUPPORTED:
        return ("matched",)
    if verdict is OracleVerdict.REFUTED:
        return ("mismatch",)
    if verdict is OracleVerdict.INCONCLUSIVE:
        return ("unresolvable",)
    if verdict is OracleVerdict.ERROR:
        return ("sut-error",)
    return ("not-applicable",)


def _detail(verdict: OracleVerdict, record: GroundTruthRecord) -> str:
    return f"{record.kind.value}:{record.match.value}:{verdict.value}"[:300]


class RedactionOracle(Oracle):
    """No credential-shaped material may survive any serialized output."""

    name = "redaction"

    def evaluate(self, context: OracleContext) -> list[OracleJudgment]:
        case = context.case
        blob = _serialize(context)
        leaks = find_leaks(blob)
        if leaks:
            verdict = OracleVerdict.REFUTED
            detail = f"leak patterns: {len(leaks)}"
        elif not context.result.ok:
            verdict = OracleVerdict.ERROR
            detail = "system output unavailable for redaction scan"
        else:
            verdict = OracleVerdict.SUPPORTED
            detail = "no credential-shaped material in serialized output"
        return [
            OracleJudgment(
                case_id=case.case_id,
                oracle=self.name,
                check=CHECK_REDACTION,
                stage=case.stage.value,
                track=case.track.value,
                verdict=verdict,
                gt_kind="",
                subject="serialized_output",
                reason_codes=("secret-material-found",) if leaks else ("clean",),
                security_relevant=True,
                disagreement=verdict in (OracleVerdict.REFUTED, OracleVerdict.ERROR),
                detail=detail,
            )
        ]


def _serialize(context: OracleContext) -> str:
    import json as _json

    chunks: list[str] = []
    for obs in context.observations:
        try:
            chunks.append(_json.dumps(obs.payload, sort_keys=True, default=str))
        except (TypeError, ValueError):
            chunks.append(str(obs.payload))
    try:
        chunks.append(_json.dumps(context.result.outputs, sort_keys=True, default=str))
    except (TypeError, ValueError):
        chunks.append(str(context.result.outputs))
    chunks.append(context.result.error_message)
    return "\n".join(chunks)


class AuthorityOracle(Oracle):
    """Authority drift is a security disagreement, whatever the label says.

    A preserved snapshot is the only accepted outcome for a read-only
    evaluation; a mutation must surface here even if the fixture forgot to
    declare it."""

    name = "authority"

    def evaluate(self, context: OracleContext) -> list[OracleJudgment]:
        case = context.case
        diff = context.authority_diff
        if diff is None:
            return []
        preserved = diff.preserved
        verdict = OracleVerdict.SUPPORTED if preserved else OracleVerdict.REFUTED
        return [
            OracleJudgment(
                case_id=case.case_id,
                oracle=self.name,
                check=CHECK_AUTHORITY,
                stage=EvaluationStage.AUTHORITY.value,
                track=case.track.value,
                verdict=verdict,
                gt_kind=GroundTruthKind.AUTHORITY_INVARIANT.value,
                subject="authority_diff.state",
                reason_codes=(diff.state.lower(),) if not preserved else ("preserved",),
                security_relevant=True,
                disagreement=not preserved,
                detail=diff.model_dump_json(),
            )
        ]


class ParityOracle(Oracle):
    """Cross-adapter agreement inside a single parity invocation."""

    name = "parity"

    def evaluate(self, context: OracleContext) -> list[OracleJudgment]:
        case = context.case
        if case.stage.value != EvaluationStage.PARITY.value:
            return []
        payload = context.result.outputs if context.result.ok else {}
        mismatches = payload.get("mismatched_fields")
        failed = payload.get("failed_interfaces")
        agreements = payload.get("interfaces_ok")
        judgments: list[OracleJudgment] = []
        if not isinstance(mismatches, (list, tuple)) and agreements is None:
            return judgments
        mismatch_list = [str(item) for item in mismatches] if isinstance(mismatches, (list, tuple)) else []
        failed_list = [str(item) for item in failed] if isinstance(failed, (list, tuple)) else []
        equal = not mismatch_list and not failed_list
        judgments.append(
            OracleJudgment(
                case_id=case.case_id,
                oracle=self.name,
                check=CHECK_PARITY,
                stage=case.stage.value,
                track=case.track.value,
                verdict=OracleVerdict.SUPPORTED if equal else OracleVerdict.REFUTED,
                gt_kind=GroundTruthKind.STATE.value,
                subject="all_equal",
                reason_codes=("interfaces-agree",) if equal else tuple(f"mismatch:{m}" for m in mismatch_list[:4]),
                security_relevant=False,
                disagreement=False,
                detail=",".join(failed_list[:4])[:200],
            )
        )
        ok_count = int(agreements) if isinstance(agreements, (int, float)) else 0
        judgments.append(
            OracleJudgment(
                case_id=case.case_id,
                oracle=self.name,
                check=CHECK_PARITY,
                stage=case.stage.value,
                track=case.track.value,
                verdict=OracleVerdict.SUPPORTED if ok_count >= 3 else OracleVerdict.REFUTED,
                gt_kind=GroundTruthKind.STATE.value,
                subject="interfaces_ok",
                reason_codes=("all-adapters-answered",) if ok_count >= 3 else ("adapter-unavailable",),
                security_relevant=False,
                disagreement=False,
                detail=f"interfaces answered: {ok_count}",
            )
        )
        return judgments


DEFAULT_ORACLE_NAMES: tuple[str, ...] = ("ground_truth", "redaction", "authority", "parity")


def default_oracles() -> tuple[Oracle, ...]:
    return (GroundTruthOracle(), RedactionOracle(), AuthorityOracle(), ParityOracle())


def select_oracles(names: Iterable[str] | None) -> tuple[Oracle, ...]:
    available = {oracle.name: oracle for oracle in default_oracles()}
    if not names:
        return default_oracles()
    chosen: list[Oracle] = []
    for name in names:
        oracle = available.get(str(name))
        if oracle is None:
            from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode

            raise EvaluationError(EvaluationErrorCode.ORACLE_REJECTED, f"unknown oracle: {name}")
        chosen.append(oracle)
    return tuple(chosen)


def security_disagreements(judgments: Sequence[OracleJudgment]) -> tuple[str, ...]:
    """Fail-closed list for the security gate."""
    reasons: list[str] = []
    for judgment in judgments:
        if judgment.security_relevant and judgment.disagreement:
            reasons.append(f"{judgment.case_id}:{judgment.check}:{judgment.verdict.value}")
    return tuple(sorted(dict.fromkeys(reasons)))


def resolve_from(
    observations: Sequence[EvaluationObservation],
    subject: str,
    *,
    stage: str = "",
) -> tuple[bool, Any]:
    payloads = [obs.payload for obs in observations if not stage or obs.stage.value == stage]
    return resolve_subject(payloads, subject)
