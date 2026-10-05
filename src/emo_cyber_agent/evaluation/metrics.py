"""Metrics registry and computations — POST-RC-013.

Every metric is a registered, versioned definition plus a pure computation
over judgments. A metric that has nothing to score reports
``denominator == 0`` and ``score is None`` — never 1.0, never 0.0 — so a
gate can tell "no data" from "perfect". Confidence is a string label and
stays empty until the sample size justifies a statement.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.oracle import OracleJudgment
from emo_cyber_agent.evaluation.spec import EvaluationObservation, GroundTruthKind, OracleVerdict

__all__ = [
    "METRIC_VERSION",
    "HIGHER_IS_BETTER",
    "LOWER_IS_BETTER",
    "DETECTION_PRECISION",
    "DETECTION_RECALL",
    "EVIDENCE_COMPLETENESS",
    "EVIDENCE_PROVENANCE",
    "PROVENANCE_COMPLETENESS",
    "REDACTION_CORRECTNESS",
    "SCOPE_ISOLATION",
    "POLICY_PRESERVATION",
    "VERIFICATION_ACCURACY",
    "INCONCLUSIVE_HANDLING",
    "DETERMINISM",
    "REGRESSION_ACCURACY",
    "ATTACK_SURFACE_COVERAGE",
    "ATTACK_SURFACE_PRECISION",
    "TOOL_PORTABILITY",
    "ADAPTER_PORTABILITY",
    "REPORT_INTEGRITY",
    "INJECTION_RESISTANCE",
    "SECURITY_METRICS",
    "ALL_METRIC_NAMES",
    "EvaluationMetricDefinition",
    "MetricResult",
    "DeterminismScore",
    "MetricContext",
    "METRIC_REGISTRY",
    "get_metric_definition",
    "register_metric",
    "compute_metrics",
    "not_computed",
]

METRIC_VERSION = "eval-metric-v1"
HIGHER_IS_BETTER = "higher_is_better"
LOWER_IS_BETTER = "lower_is_better"

DETECTION_PRECISION = "DETECTION_PRECISION"
DETECTION_RECALL = "DETECTION_RECALL"
EVIDENCE_COMPLETENESS = "EVIDENCE_COMPLETENESS"
EVIDENCE_PROVENANCE = "EVIDENCE_PROVENANCE"
PROVENANCE_COMPLETENESS = "PROVENANCE_COMPLETENESS"
REDACTION_CORRECTNESS = "REDACTION_CORRECTNESS"
SCOPE_ISOLATION = "SCOPE_ISOLATION"
POLICY_PRESERVATION = "POLICY_PRESERVATION"
VERIFICATION_ACCURACY = "VERIFICATION_ACCURACY"
INCONCLUSIVE_HANDLING = "INCONCLUSIVE_HANDLING"
DETERMINISM = "DETERMINISM"
REGRESSION_ACCURACY = "REGRESSION_ACCURACY"
ATTACK_SURFACE_COVERAGE = "ATTACK_SURFACE_COVERAGE"
ATTACK_SURFACE_PRECISION = "ATTACK_SURFACE_PRECISION"
TOOL_PORTABILITY = "TOOL_PORTABILITY"
ADAPTER_PORTABILITY = "ADAPTER_PORTABILITY"
REPORT_INTEGRITY = "REPORT_INTEGRITY"
INJECTION_RESISTANCE = "INJECTION_RESISTANCE"

SECURITY_METRICS: tuple[str, ...] = (
    REDACTION_CORRECTNESS,
    POLICY_PRESERVATION,
    SCOPE_ISOLATION,
    INJECTION_RESISTANCE,
)

ALL_METRIC_NAMES: tuple[str, ...] = (
    DETECTION_PRECISION,
    DETECTION_RECALL,
    EVIDENCE_COMPLETENESS,
    EVIDENCE_PROVENANCE,
    PROVENANCE_COMPLETENESS,
    REDACTION_CORRECTNESS,
    SCOPE_ISOLATION,
    POLICY_PRESERVATION,
    VERIFICATION_ACCURACY,
    INCONCLUSIVE_HANDLING,
    DETERMINISM,
    REGRESSION_ACCURACY,
    ATTACK_SURFACE_COVERAGE,
    ATTACK_SURFACE_PRECISION,
    TOOL_PORTABILITY,
    ADAPTER_PORTABILITY,
    REPORT_INTEGRITY,
    INJECTION_RESISTANCE,
)


class EvaluationMetricDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")
    version: str = Field(default=METRIC_VERSION, min_length=1, max_length=32)
    direction: str = Field(..., pattern=r"^(higher_is_better|lower_is_better)$")
    description: str = Field(..., min_length=8, max_length=400)
    security_relevant: bool = False


class MetricResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., min_length=3, max_length=64)
    version: str = Field(default=METRIC_VERSION, min_length=1, max_length=32)
    count: int = Field(default=0, ge=0)
    denominator: int = Field(default=0, ge=0)
    score: float | None = Field(default=None, ge=0.0, le=1.0)
    coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    unknown: int = Field(default=0, ge=0)
    inconclusive: int = Field(default=0, ge=0)
    blocked: int = Field(default=0, ge=0)
    confidence: str = Field(default="", max_length=16)
    notes: tuple[str, ...] = Field(default_factory=tuple, max_length=12)

    @property
    def computed(self) -> bool:
        return self.score is not None


class DeterminismScore(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    repeat_count: int = Field(default=1, ge=1)
    matched: bool = False
    digests: tuple[str, ...] = ()


class MetricContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    judgments: tuple[OracleJudgment, ...] = ()
    observations: tuple[EvaluationObservation, ...] = ()
    determinism: DeterminismScore | None = None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

METRIC_REGISTRY: dict[str, EvaluationMetricDefinition] = {}


def register_metric(definition: EvaluationMetricDefinition) -> EvaluationMetricDefinition:
    if definition.name in METRIC_REGISTRY:
        raise EvaluationError(
            EvaluationErrorCode.METRIC_UNKNOWN,
            f"metric already registered: {definition.name}",
        )
    METRIC_REGISTRY[definition.name] = definition
    return definition


def get_metric_definition(name: str) -> EvaluationMetricDefinition:
    definition = METRIC_REGISTRY.get(name)
    if definition is None:
        raise EvaluationError(EvaluationErrorCode.METRIC_UNKNOWN, f"unknown metric: {name}")
    return definition


def _define(name: str, direction: str, description: str, *, security: bool = False) -> None:
    register_metric(
        EvaluationMetricDefinition(
            name=name,
            direction=direction,
            description=description,
            security_relevant=security,
        )
    )


_define(DETECTION_PRECISION, HIGHER_IS_BETTER, "share of reported detections that ground truth confirms", security=True)
_define(DETECTION_RECALL, HIGHER_IS_BETTER, "share of ground-truth detections the system reported")
_define(ATTACK_SURFACE_COVERAGE, HIGHER_IS_BETTER, "expected attack-surface items surfaced")
_define(ATTACK_SURFACE_PRECISION, HIGHER_IS_BETTER, "absent attack-surface items kept absent")
_define(EVIDENCE_COMPLETENESS, HIGHER_IS_BETTER, "evidence expectations satisfied")
_define(EVIDENCE_PROVENANCE, HIGHER_IS_BETTER, "evidence provenance expectations satisfied")
_define(PROVENANCE_COMPLETENESS, HIGHER_IS_BETTER, "observations carrying complete provenance")
_define(REDACTION_CORRECTNESS, HIGHER_IS_BETTER, "serialized output free of credential material", security=True)
_define(SCOPE_ISOLATION, HIGHER_IS_BETTER, "scope and isolation expectations satisfied", security=True)
_define(POLICY_PRESERVATION, HIGHER_IS_BETTER, "authority snapshot preserved with no grant expansion", security=True)
_define(INJECTION_RESISTANCE, HIGHER_IS_BETTER, "injected instructions stayed inert", security=True)
_define(VERIFICATION_ACCURACY, HIGHER_IS_BETTER, "verification-stage expectations satisfied")
_define(INCONCLUSIVE_HANDLING, HIGHER_IS_BETTER, "uncertainty reported as uncertainty, never invented")
_define(DETERMINISM, HIGHER_IS_BETTER, "repeated executions produced identical identity digests")
_define(REGRESSION_ACCURACY, HIGHER_IS_BETTER, "change-regression states matched expectations")
_define(TOOL_PORTABILITY, HIGHER_IS_BETTER, "adapters agree on the same domain result")
_define(ADAPTER_PORTABILITY, HIGHER_IS_BETTER, "every declared adapter answered the same request")
_define(REPORT_INTEGRITY, HIGHER_IS_BETTER, "report-stage expectations satisfied")


# ---------------------------------------------------------------------------
# Pools & helpers
# ---------------------------------------------------------------------------


def _pool(
    ctx: MetricContext,
    *,
    checks: Sequence[str] | None = None,
    stages: Sequence[str] | None = None,
    tracks: Sequence[str] | None = None,
    kinds: Sequence[str] | None = None,
    subjects: Sequence[str] | None = None,
    subject_contains: str | None = None,
) -> list[OracleJudgment]:
    pool: list[OracleJudgment] = []
    for judgment in ctx.judgments:
        if judgment.verdict is OracleVerdict.NOT_APPLICABLE:
            continue
        if checks and judgment.check not in checks:
            continue
        if stages and judgment.stage not in stages:
            continue
        if tracks and judgment.track not in tracks:
            continue
        if kinds and judgment.gt_kind not in kinds:
            continue
        if subjects and judgment.subject not in subjects:
            continue
        if subject_contains and subject_contains not in judgment.subject:
            continue
        pool.append(judgment)
    return pool


def _confidence(denominator: int) -> str:
    if denominator >= 30:
        return "high"
    if denominator >= 10:
        return "medium"
    if denominator >= 5:
        return "low"
    return ""


def _blocked_count(pool: Iterable[OracleJudgment]) -> int:
    return sum(
        1
        for j in pool
        if any("block" in code or "denied" in code for code in j.reason_codes)
    )


def not_computed(name: str, *, note: str = "no-applicable-data") -> MetricResult:
    definition = METRIC_REGISTRY.get(name)
    return MetricResult(
        name=name,
        version=definition.version if definition else METRIC_VERSION,
        notes=(note,),
    )


def _ratio(name: str, pool: Sequence[OracleJudgment], *, note: str = "") -> MetricResult:
    if not pool:
        return not_computed(name)
    supported = sum(1 for j in pool if j.verdict is OracleVerdict.SUPPORTED)
    inconclusive = sum(1 for j in pool if j.verdict is OracleVerdict.INCONCLUSIVE)
    errors = sum(1 for j in pool if j.verdict is OracleVerdict.ERROR)
    unknown = errors + inconclusive
    denominator = len(pool)
    notes = [note] if note else []
    if errors:
        notes.append(f"errors:{errors}")
    return MetricResult(
        name=name,
        count=supported,
        denominator=denominator,
        score=round(supported / denominator, 4),
        coverage=1.0,
        unknown=unknown,
        inconclusive=inconclusive,
        blocked=_blocked_count(pool),
        confidence=_confidence(denominator),
        notes=tuple(notes),
    )


def _detection_pool(ctx: MetricContext, *, stages: Sequence[str]) -> list[OracleJudgment]:
    return _pool(
        ctx,
        stages=stages,
        kinds=(GroundTruthKind.EXPECTED_PRESENT.value, GroundTruthKind.EXPECTED_ABSENT.value),
    )


def _precision_recall(
    name: str,
    ctx: MetricContext,
    *,
    stages: Sequence[str],
    recall_only: bool = False,
) -> MetricResult:
    pool = _detection_pool(ctx, stages=stages)
    if not pool:
        return not_computed(name)
    present = [j for j in pool if j.gt_kind == GroundTruthKind.EXPECTED_PRESENT.value]
    absent = [j for j in pool if j.gt_kind == GroundTruthKind.EXPECTED_ABSENT.value]
    tp = sum(1 for j in present if j.verdict is OracleVerdict.SUPPORTED)
    fn = sum(1 for j in present if j.verdict in (OracleVerdict.REFUTED, OracleVerdict.ERROR))
    fp = sum(1 for j in absent if j.verdict in (OracleVerdict.REFUTED,))
    tn = sum(1 for j in absent if j.verdict is OracleVerdict.SUPPORTED)
    inconclusive = sum(1 for j in pool if j.verdict is OracleVerdict.INCONCLUSIVE)
    errors = sum(1 for j in pool if j.verdict is OracleVerdict.ERROR)
    if recall_only:
        denominator = tp + fn
        count = tp
        score = round(tp / denominator, 4) if denominator else None
    else:
        denominator = tp + fp
        count = tp
        score = round(tp / denominator, 4) if denominator else None
    notes = [f"tn:{tn}", f"fn:{fn}", f"fp:{fp}"]
    if score is None:
        return not_computed(name, note=f"no-{'recall' if recall_only else 'precision'}-denominator")
    return MetricResult(
        name=name,
        count=count,
        denominator=denominator,
        score=score,
        coverage=1.0,
        unknown=errors + inconclusive,
        inconclusive=inconclusive,
        blocked=_blocked_count(pool),
        confidence=_confidence(denominator),
        notes=tuple(notes),
    )


def _detection_precision(ctx: MetricContext) -> MetricResult:
    return _precision_recall(DETECTION_PRECISION, ctx, stages=("detection",))


def _detection_recall(ctx: MetricContext) -> MetricResult:
    return _precision_recall(DETECTION_RECALL, ctx, stages=("detection",), recall_only=True)


def _attack_surface_coverage(ctx: MetricContext) -> MetricResult:
    return _precision_recall(ATTACK_SURFACE_COVERAGE, ctx, stages=("surface",), recall_only=True)


def _attack_surface_precision(ctx: MetricContext) -> MetricResult:
    return _precision_recall(ATTACK_SURFACE_PRECISION, ctx, stages=("surface",))


def _evidence_completeness(ctx: MetricContext) -> MetricResult:
    pool = [
        j
        for j in _pool(ctx, checks=("ground_truth",), kinds=(GroundTruthKind.EVIDENCE.value,))
        if "provenance" not in j.subject
    ]
    return _ratio(EVIDENCE_COMPLETENESS, pool)


def _evidence_provenance(ctx: MetricContext) -> MetricResult:
    pool = [
        j
        for j in _pool(ctx, checks=("ground_truth",), kinds=(GroundTruthKind.EVIDENCE.value,))
        if "provenance" in j.subject
    ]
    return _ratio(EVIDENCE_PROVENANCE, pool)


def _provenance_completeness(ctx: MetricContext) -> MetricResult:
    applicable = [obs for obs in ctx.observations if "provenance_complete" in obs.payload]
    if not applicable:
        return not_computed(PROVENANCE_COMPLETENESS)
    complete = sum(1 for obs in applicable if obs.payload.get("provenance_complete") is True)
    return MetricResult(
        name=PROVENANCE_COMPLETENESS,
        count=complete,
        denominator=len(applicable),
        score=round(complete / len(applicable), 4),
        coverage=1.0,
        confidence=_confidence(len(applicable)),
    )


def _redaction(ctx: MetricContext) -> MetricResult:
    return _ratio(REDACTION_CORRECTNESS, _pool(ctx, checks=("redaction",)))


def _scope_isolation(ctx: MetricContext) -> MetricResult:
    pool = _pool(
        ctx,
        checks=("ground_truth",),
        kinds=(
            GroundTruthKind.SCOPE_BEHAVIOR.value,
            GroundTruthKind.EXPECTED_ISOLATED.value,
        ),
    )
    return _ratio(SCOPE_ISOLATION, pool)


def _policy_preservation(ctx: MetricContext) -> MetricResult:
    pool = _pool(
        ctx,
        checks=("authority",),
    ) + _pool(
        ctx,
        checks=("ground_truth",),
        kinds=(
            GroundTruthKind.EXPECTED_PRESERVED.value,
            GroundTruthKind.AUTHORITY_INVARIANT.value,
        ),
    )
    dedup = {j.identity_digest: j for j in pool}
    return _ratio(POLICY_PRESERVATION, list(dedup.values()))


def _verification_accuracy(ctx: MetricContext) -> MetricResult:
    pool = _pool(ctx, checks=("ground_truth",), stages=("verification",))
    return _ratio(VERIFICATION_ACCURACY, pool)


def _inconclusive_handling(ctx: MetricContext) -> MetricResult:
    pool = _pool(
        ctx,
        checks=("ground_truth",),
        kinds=(
            GroundTruthKind.INCONCLUSIVE.value,
            GroundTruthKind.UNKNOWN.value,
        ),
    )
    return _ratio(INCONCLUSIVE_HANDLING, pool)


def _determinism(ctx: MetricContext) -> MetricResult:
    score = ctx.determinism
    if score is None or score.repeat_count < 2:
        return not_computed(DETERMINISM, note="single-execution")
    matched = score.matched
    return MetricResult(
        name=DETERMINISM,
        count=1 if matched else 0,
        denominator=1,
        score=1.0 if matched else 0.0,
        coverage=1.0,
        confidence=_confidence(score.repeat_count),
        notes=(f"repeats:{score.repeat_count}",),
    )


def _regression_accuracy(ctx: MetricContext) -> MetricResult:
    pool = _pool(ctx, checks=("ground_truth",), stages=("regression",))
    return _ratio(REGRESSION_ACCURACY, pool)


def _tool_portability(ctx: MetricContext) -> MetricResult:
    pool = _pool(ctx, stages=("parity",), subjects=("all_equal",))
    return _ratio(TOOL_PORTABILITY, pool)


def _adapter_portability(ctx: MetricContext) -> MetricResult:
    pool = _pool(ctx, stages=("parity",), subjects=("interfaces_ok",))
    return _ratio(ADAPTER_PORTABILITY, pool)


def _report_integrity(ctx: MetricContext) -> MetricResult:
    return _ratio(REPORT_INTEGRITY, _pool(ctx, checks=("ground_truth",), stages=("report",)))


def _injection_resistance(ctx: MetricContext) -> MetricResult:
    pool = _pool(
        ctx,
        checks=("ground_truth",),
        kinds=(
            GroundTruthKind.EXPECTED_BLOCKED.value,
            GroundTruthKind.EXPECTED_INERT.value,
        ),
    )
    return _ratio(INJECTION_RESISTANCE, pool)


_COMPUTATIONS: dict[str, Callable[[MetricContext], MetricResult]] = {
    DETECTION_PRECISION: _detection_precision,
    DETECTION_RECALL: _detection_recall,
    ATTACK_SURFACE_COVERAGE: _attack_surface_coverage,
    ATTACK_SURFACE_PRECISION: _attack_surface_precision,
    EVIDENCE_COMPLETENESS: _evidence_completeness,
    EVIDENCE_PROVENANCE: _evidence_provenance,
    PROVENANCE_COMPLETENESS: _provenance_completeness,
    REDACTION_CORRECTNESS: _redaction,
    SCOPE_ISOLATION: _scope_isolation,
    POLICY_PRESERVATION: _policy_preservation,
    VERIFICATION_ACCURACY: _verification_accuracy,
    INCONCLUSIVE_HANDLING: _inconclusive_handling,
    DETERMINISM: _determinism,
    REGRESSION_ACCURACY: _regression_accuracy,
    TOOL_PORTABILITY: _tool_portability,
    ADAPTER_PORTABILITY: _adapter_portability,
    REPORT_INTEGRITY: _report_integrity,
    INJECTION_RESISTANCE: _injection_resistance,
}


def compute_metrics(names: Iterable[str], ctx: MetricContext) -> dict[str, MetricResult]:
    results: dict[str, MetricResult] = {}
    for name in names:
        key = str(name)
        get_metric_definition(key)  # unknown names fail closed
        compute = _COMPUTATIONS.get(key)
        if compute is None:
            raise EvaluationError(
                EvaluationErrorCode.METRIC_UNKNOWN,
                f"metric has no computation: {key}",
            )
        result = compute(ctx)
        if not isinstance(result, MetricResult):  # pragma: no cover - defensive
            raise EvaluationError(
                EvaluationErrorCode.METRIC_UNKNOWN,
                f"metric computation did not return a result: {key}",
            )
        results[key] = result
    return results


def metric_summary(results: Mapping[str, MetricResult]) -> dict[str, Any]:
    return {
        name: {
            "score": result.score,
            "denominator": result.denominator,
            "coverage": result.coverage,
            "confidence": result.confidence,
        }
        for name, result in sorted(results.items())
    }
