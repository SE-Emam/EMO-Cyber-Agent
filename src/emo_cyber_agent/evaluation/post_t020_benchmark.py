"""POST-T020 benchmark spec — G9-A (Benchmark Architect).

Spec module only: category taxonomy, case schema, and metric *definitions*.
This module defines no scores, computes no metrics, and issues no verdicts —
it only names which registered metrics the evaluator (G9-C) must compute via
:func:`emo_cyber_agent.evaluation.metrics.compute_metrics` and which gates
apply via :func:`emo_cyber_agent.evaluation.gates.evaluate_gates`.

Reuse (no duplication):

- metric definitions live in ``evaluation/metrics.py`` (``METRIC_REGISTRY``);
  this module only aliases generic POST-T020 names to registry names and
  validates them with :func:`get_metric_definition` — nothing is registered
  here;
- case-identity conventions mirror ``evaluation/cases.py`` (case-id shape,
  blind projection refusing ground-truth fields, production sources refused);
- ground-truth semantics come from ``evaluation/ground_truth.py``
  (``GroundTruthRecord``) and ``evaluation/spec.py``
  (``SECURITY_GROUND_TRUTH_KINDS``);
- contamination control stays in ``evaluation/datasets.py``
  (:func:`contamination_scan`); it is referenced, not reimplemented.

Baseline rule: counts below were obtained by counting files on disk
(``ls``/``find`` over ``tests/fixtures/evaluation/``); no fixture was
executed and no system under test was invoked. :func:`count_corpus_files`
lets a later agent recount without executing anything.
"""

from __future__ import annotations

import copy
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from emo_cyber_agent.evaluation.cases import CaseSource
from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.ground_truth import GroundTruthRecord
from emo_cyber_agent.evaluation.metrics import EvaluationMetricDefinition, get_metric_definition
from emo_cyber_agent.evaluation.spec import SECURITY_GROUND_TRUTH_KINDS

__all__ = [
    "POST_T020_VERSION",
    "POST_T020_CASE_ID",
    "PostT020Category",
    "PostT020CaseKind",
    "SECTION_PRIMARY",
    "CATEGORY_SOURCES",
    "POST_T020_BASELINE_SECTIONS",
    "POST_T020_BASELINE_CASE_FILES",
    "POST_T020_BASELINE_FILES_TOTAL",
    "POST_T020_CATEGORY_ROLLUP",
    "POST_T020_METRIC_ALIASES",
    "POST_T020_SUPPORTING_METRICS",
    "PostT020Case",
    "post_t020_blind",
    "resolve_post_t020_metrics",
    "count_corpus_files",
    "verify_baseline",
]

POST_T020_VERSION = "post-t020-g9-v1"

# Mirrors the case-id shape enforced by evaluation/cases.py (kept local so
# this spec does not import a private name).
POST_T020_CASE_ID = r"^[a-z0-9][a-z0-9._-]{1,95}$"

# Fields that must never appear in system-visible input (mirrors the
# blind_case refusal list in evaluation/cases.py, extended with this spec's
# own evaluation-only field names).
_FORBIDDEN_INPUT_KEYS = frozenset(
    {
        "ground_truth",
        "expected",
        "expected_signal",
        "must_not",
        "label",
        "verdict",
    }
)


def _find_forbidden_input_paths(node: object, *, prefix: str = "input") -> list[str]:
    """Recursively collect dotted paths where a forbidden key appears.

    G11-M3: top-level-only checks let ``input.context.ground_truth`` leak
    ground truth into system-visible input. Any nested mapping key in
    ``_FORBIDDEN_INPUT_KEYS`` is a leak, at any depth, inside dicts/lists/
    tuples.
    """
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if key in _FORBIDDEN_INPUT_KEYS:
                found.append(path)
            found.extend(_find_forbidden_input_paths(value, prefix=path))
    elif isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            found.extend(_find_forbidden_input_paths(item, prefix=f"{prefix}[{index}]"))
    return found


class PostT020Category(StrEnum):
    """The 12 POST-T020 benchmark categories."""

    CODE = "code"
    APPLICATION = "application"
    AGENT = "agent"
    PROMPT = "prompt"
    MCP = "mcp"
    CLOUD = "cloud"
    CONTAMINATION = "contamination"
    DELEGATION = "delegation"
    RECOVERY = "recovery"
    CHANGE = "change"
    THREAT_MODEL = "threat_model"
    VERIFICATION = "verification"


class PostT020CaseKind(StrEnum):
    """Closed case-kind vocabulary.

    ``cross_scope`` is the machine value; reports may render it
    ``cross-scope``.
    """

    POSITIVE = "positive"
    NEGATIVE = "negative"
    AMBIGUOUS = "ambiguous"
    ADVERSARIAL = "adversarial"
    REGRESSION = "regression"
    CROSS_SCOPE = "cross_scope"


# ---------------------------------------------------------------------------
# Taxonomy: old corpus sections -> new categories
# ---------------------------------------------------------------------------
#
# Each old section has exactly one primary category so file counts roll up
# without double-counting; secondary feeds are non-counting attribution for
# case authorship (G9-B). Five categories start at zero direct coverage —
# those are the gaps G9-B must fill with new cases, not a recount artifact.

SECTION_PRIMARY: dict[str, PostT020Category] = {
    "web": PostT020Category.APPLICATION,
    "authorization": PostT020Category.APPLICATION,
    "hostile_input": PostT020Category.PROMPT,
    "dependency": PostT020Category.CODE,
    "secrets": PostT020Category.CODE,
    "mcp": PostT020Category.MCP,
    "agent": PostT020Category.AGENT,
    "memory": PostT020Category.AGENT,
    "change": PostT020Category.CHANGE,
    "verification": PostT020Category.VERIFICATION,
    "adversarial": PostT020Category.PROMPT,
}

CATEGORY_SOURCES: dict[str, dict[str, tuple[str, ...]]] = {
    PostT020Category.CODE.value: {
        "primary_sections": ("dependency", "secrets"),
        "secondary_sections": ("web", "adversarial"),
    },
    PostT020Category.APPLICATION.value: {
        "primary_sections": ("web", "authorization"),
        "secondary_sections": ("dependency", "secrets"),
    },
    PostT020Category.AGENT.value: {
        "primary_sections": ("agent", "memory"),
        "secondary_sections": ("mcp",),
    },
    PostT020Category.PROMPT.value: {
        "primary_sections": ("hostile_input", "adversarial"),
        "secondary_sections": ("memory",),
    },
    PostT020Category.MCP.value: {
        "primary_sections": ("mcp",),
        "secondary_sections": ("agent",),
    },
    PostT020Category.CLOUD.value: {
        "primary_sections": (),
        "secondary_sections": ("dependency",),
    },
    PostT020Category.CONTAMINATION.value: {
        "primary_sections": (),
        "secondary_sections": ("hostile_input", "memory", "secrets"),
    },
    PostT020Category.DELEGATION.value: {
        "primary_sections": (),
        "secondary_sections": ("agent", "mcp", "authorization"),
    },
    PostT020Category.RECOVERY.value: {
        "primary_sections": (),
        "secondary_sections": ("change",),
    },
    PostT020Category.CHANGE.value: {
        "primary_sections": ("change",),
        "secondary_sections": (),
    },
    PostT020Category.THREAT_MODEL.value: {
        "primary_sections": (),
        "secondary_sections": ("verification", "adversarial"),
    },
    PostT020Category.VERIFICATION.value: {
        "primary_sections": ("verification",),
        "secondary_sections": ("change",),
    },
}


# ---------------------------------------------------------------------------
# Baseline: file counts, recorded 2026-10-06 (counted, not executed)
# ---------------------------------------------------------------------------
#
# Method: ``for d in tests/fixtures/evaluation/*/`` counting entries plus
# ``find tests/fixtures/evaluation -type f``. All files are ``*.json``.
# 104 case documents + 1 ``dataset.json`` manifest (which declares
# ``case_count: 104`` — consistent) = 105 files.

POST_T020_BASELINE_SECTIONS: dict[str, int] = {
    "adversarial": 10,
    "agent": 8,
    "authorization": 12,
    "change": 8,
    "dependency": 8,
    "hostile_input": 10,
    "mcp": 8,
    "memory": 8,
    "secrets": 10,
    "verification": 10,
    "web": 12,
}

POST_T020_BASELINE_CASE_FILES = 104
POST_T020_BASELINE_FILES_TOTAL = 105  # 104 cases + dataset.json

# Primary-category roll-up (exact partition of the 104 case files; gap
# categories are explicitly zero, to be filled by G9-B authorship).
POST_T020_CATEGORY_ROLLUP: dict[str, int] = {
    PostT020Category.CODE.value: 18,  # dependency 8 + secrets 10
    PostT020Category.APPLICATION.value: 24,  # web 12 + authorization 12
    PostT020Category.AGENT.value: 16,  # agent 8 + memory 8
    PostT020Category.PROMPT.value: 20,  # hostile_input 10 + adversarial 10
    PostT020Category.MCP.value: 8,
    PostT020Category.CLOUD.value: 0,
    PostT020Category.CONTAMINATION.value: 0,
    PostT020Category.DELEGATION.value: 0,
    PostT020Category.RECOVERY.value: 0,
    PostT020Category.CHANGE.value: 8,
    PostT020Category.THREAT_MODEL.value: 0,
    PostT020Category.VERIFICATION.value: 10,
}


# ---------------------------------------------------------------------------
# Metric definitions: aliases into evaluation/metrics.py (no new metrics)
# ---------------------------------------------------------------------------
#
# Generic POST-T020 names on the left, registry names on the right. FP/FN are
# *derived counts* reported inside DETECTION_PRECISION/DETECTION_RECALL notes
# (``fp:``/``fn:``/``tn:``), not registry metrics — no new metric is
# registered here. There is deliberately NO aggregate "security score":
# security-relevant signal flows through POLICY_PRESERVATION, SCOPE_ISOLATION,
# REDACTION_CORRECTNESS and INJECTION_RESISTANCE into the fail-closed
# security gate; an average must never override a failed gate.

POST_T020_METRIC_ALIASES: dict[str, tuple[str, ...]] = {
    "precision": ("DETECTION_PRECISION",),
    "recall": ("DETECTION_RECALL",),
    "agreement": ("TOOL_PORTABILITY", "ADAPTER_PORTABILITY"),
    "determinism": ("DETERMINISM",),
    "isolation": ("SCOPE_ISOLATION",),
    "recovery_classification": ("REGRESSION_ACCURACY",),
}

# Supporting registry metrics per case-kind / category concern. Reused as-is;
# the evaluator selects the subset applicable to the cases it runs.
POST_T020_SUPPORTING_METRICS: dict[str, tuple[str, ...]] = {
    "ambiguous": ("INCONCLUSIVE_HANDLING",),
    "adversarial": ("INJECTION_RESISTANCE",),
    "authority_leak": ("POLICY_PRESERVATION", "REDACTION_CORRECTNESS"),
    "verification": ("VERIFICATION_ACCURACY",),
    "threat_model": ("ATTACK_SURFACE_COVERAGE", "ATTACK_SURFACE_PRECISION"),
    "report": ("REPORT_INTEGRITY",),
    "evidence": (
        "EVIDENCE_COMPLETENESS",
        "EVIDENCE_PROVENANCE",
        "PROVENANCE_COMPLETENESS",
    ),
}

_FP_FN_NOTE = (
    "FP/FN are derived counts from the DETECTION_PRECISION/DETECTION_RECALL "
    "notes (fp:/fn:/tn:), not standalone metrics; no security score is defined."
)


def resolve_post_t020_metrics() -> dict[str, EvaluationMetricDefinition]:
    """Validate every aliased and supporting name against the registry.

    Returns the referenced definitions. Raises fail-closed on any unknown
    name. Computes nothing and scores nothing.
    """
    resolved: dict[str, EvaluationMetricDefinition] = {}
    for group in (POST_T020_METRIC_ALIASES, POST_T020_SUPPORTING_METRICS):
        for names in group.values():
            for name in names:
                resolved.setdefault(name, get_metric_definition(name))
    return resolved


# ---------------------------------------------------------------------------
# Case schema
# ---------------------------------------------------------------------------


class PostT020Case(BaseModel):
    """One POST-T020 benchmark case (spec shape, evaluation-owned).

    ``input`` is the only system-visible field (delivered blind).
    ``expected_signal`` and ``must_not`` are evaluation-only ground truth and
    must never reach the system under test (see :func:`post_t020_blind`).
    ``must_not`` carries authority-leak assertions: every record must use a
    security-relevant ground-truth kind (no grant expansion, no finding
    mutation, no secret material in output, isolation preserved).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(..., pattern=POST_T020_CASE_ID)
    title: str = Field(..., min_length=1, max_length=200)
    category: PostT020Category
    secondary_categories: tuple[PostT020Category, ...] = Field(default=(), max_length=3)
    kind: PostT020CaseKind
    input: dict[str, Any] = Field(default_factory=dict)
    expected_signal: tuple[GroundTruthRecord, ...] = Field(min_length=1, max_length=32)
    must_not: tuple[GroundTruthRecord, ...] = Field(default=(), max_length=16)
    source: CaseSource = Field(
        default_factory=lambda: CaseSource(system="internal", fixture="post-t020")
    )
    notes: str = Field(default="", max_length=1000)

    @field_validator("input")
    @classmethod
    def _no_leak_keys(cls, v: dict[str, Any]) -> dict[str, Any]:
        # G11-M3: recursive scan — nested input.*.ground_truth (or any nested
        # evaluation-answer key) is refused at construction, fail closed.
        nested = _find_forbidden_input_paths(v)
        if nested:
            raise ValueError(f"input carries evaluation-only keys: {sorted(nested)}")
        return v

    @field_validator("must_not")
    @classmethod
    def _security_kinds_only(
        cls, v: tuple[GroundTruthRecord, ...]
    ) -> tuple[GroundTruthRecord, ...]:
        allowed = set(SECURITY_GROUND_TRUTH_KINDS)
        for record in v:
            if record.kind.value not in allowed:
                raise ValueError(
                    f"must_not record {record.record_id or record.kind.value} "
                    f"must use a security ground-truth kind, got {record.kind.value}"
                )
        return v

    @model_validator(mode="after")
    def _kind_consistency(self) -> PostT020Case:
        if self.kind is PostT020CaseKind.CROSS_SCOPE and not self.secondary_categories:
            raise ValueError("cross_scope kind requires at least one secondary category")
        if self.kind is not PostT020CaseKind.CROSS_SCOPE and self.secondary_categories:
            raise ValueError("secondary categories are only allowed for cross_scope kind")
        if self.kind is PostT020CaseKind.REGRESSION and not any(
            r.stage == "regression" for r in self.expected_signal
        ):
            raise ValueError("regression kind requires a regression-stage expected signal")
        if self.kind in (
            PostT020CaseKind.ADVERSARIAL,
            PostT020CaseKind.CROSS_SCOPE,
        ) and not self.must_not:
            raise ValueError(f"{self.kind.value} kind requires non-empty must_not assertions")
        if self.source.production:
            raise ValueError("production-sourced cases are refused")
        return self


def post_t020_blind(case: PostT020Case | Mapping[str, Any]) -> dict[str, Any]:
    """Project a case onto the system-visible (blind) shape.

    Returns only ``case_id``, ``title``, ``category``,
    ``secondary_categories``, ``kind`` and ``input``. A mapping that still
    carries evaluation-only fields is refused outright, mirroring
    ``blind_case`` in ``evaluation/cases.py``. G11-M3: nested
    ``input.*`` mappings carrying evaluation-answer keys are also refused,
    and ``input`` is deep-copied so the projection shares no nested objects
    with the case.
    """
    if isinstance(case, PostT020Case):
        # Defense in depth: construction already refuses nested leaks, but
        # re-scan at projection time (fail closed) in case the instance was
        # built before the recursive check existed.
        nested = _find_forbidden_input_paths(case.input)
        if nested:
            raise EvaluationError(
                EvaluationErrorCode.BLIND_ACCESS_DENIED,
                f"blind projection refuses nested evaluation-only keys: {', '.join(sorted(nested))}",
            )
        return {
            "case_id": case.case_id,
            "title": case.title,
            "category": case.category.value,
            "secondary_categories": [c.value for c in case.secondary_categories],
            "kind": case.kind.value,
            "input": copy.deepcopy(case.input),
        }
    data = dict(case)
    leaked = [k for k in ("expected_signal", "must_not", "ground_truth", "expected", "label", "verdict") if k in data]
    if leaked:
        raise EvaluationError(
            EvaluationErrorCode.BLIND_ACCESS_DENIED,
            f"blind projection refuses evaluation-only fields: {', '.join(leaked)}",
        )
    raw_input = data.get("input", {})
    if isinstance(raw_input, dict):
        nested = _find_forbidden_input_paths(raw_input)
        if nested:
            raise EvaluationError(
                EvaluationErrorCode.BLIND_ACCESS_DENIED,
                f"blind projection refuses nested evaluation-only keys: {', '.join(sorted(nested))}",
            )
    projected = {k: data[k] for k in ("case_id", "title", "category", "kind", "input") if k in data}
    if "input" in projected:
        projected["input"] = copy.deepcopy(projected["input"])
    if "secondary_categories" in data:
        projected["secondary_categories"] = copy.deepcopy(data["secondary_categories"])
    return projected


# ---------------------------------------------------------------------------
# Baseline recount (file counting only — never executes fixtures)
# ---------------------------------------------------------------------------


def count_corpus_files(corpus_root: str | Path) -> dict[str, int]:
    """Count ``*.json`` case files per section directory.

    Pure directory listing; no fixture is parsed, no SUT is invoked.
    The ``dataset.json`` manifest is excluded from per-section counts.
    """
    base = Path(corpus_root)
    counts: dict[str, int] = {}
    for section in sorted(POST_T020_BASELINE_SECTIONS):
        section_dir = base / section
        if not section_dir.is_dir():
            counts[section] = 0
            continue
        counts[section] = sum(
            1 for p in sorted(section_dir.glob("*.json")) if p.is_file()
        )
    return counts


def verify_baseline(corpus_root: str | Path) -> dict[str, Any]:
    """Compare a live recount against the recorded baseline constants."""
    live = count_corpus_files(corpus_root)
    mismatches = {
        section: {"recorded": POST_T020_BASELINE_SECTIONS[section], "found": found}
        for section, found in live.items()
        if found != POST_T020_BASELINE_SECTIONS[section]
    }
    total = sum(live.values())
    return {
        "recorded_sections": dict(POST_T020_BASELINE_SECTIONS),
        "live_sections": live,
        "recorded_case_files": POST_T020_BASELINE_CASE_FILES,
        "live_case_files": total,
        "matches": not mismatches and total == POST_T020_BASELINE_CASE_FILES,
        "mismatches": mismatches,
    }
