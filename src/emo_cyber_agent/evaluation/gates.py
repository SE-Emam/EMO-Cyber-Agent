"""Gates — POST-RC-013.

Three gates decide whether a run may ship. Gates are fail-closed:

- ``SECURITY_GATE`` fails on any security-relevant disagreement, on a
  missing or uncomputed security metric, and when a dataset declares no
  security metrics at all;
- ``CORRECTNESS_GATE`` fails when a required or thresholded metric is
  absent, uncomputed, or below its declared threshold;
- ``REGRESSION_GATE`` reports ``NOT_EVALUATED`` when no baseline exists,
  and fails when a required regression metric drops below baseline.

An aggregate score can never override a failed gate: ``overall`` is FAIL
the moment any gate fails, and the evaluation report says so in words.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.metrics import (
    HIGHER_IS_BETTER,
    LOWER_IS_BETTER,
    SECURITY_METRICS,
    MetricResult,
    get_metric_definition,
)
from emo_cyber_agent.evaluation.spec import GateName, GateStatus

__all__ = [
    "GateResult",
    "GateEvaluation",
    "evaluate_gates",
    "AGGREGATE_NOTE",
]

AGGREGATE_NOTE = (
    "overall reflects gate outcomes only; aggregate or average scores never "
    "override a failed gate"
)


class GateResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: GateName
    status: GateStatus
    required: bool = False
    reasons: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    metrics: tuple[str, ...] = Field(default_factory=tuple, max_length=32)


class GateEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    overall: GateStatus
    results: tuple[GateResult, ...]
    thresholds: dict[str, float] = Field(default_factory=dict)
    required_metrics: tuple[str, ...] = Field(default_factory=tuple)
    required_gates: tuple[str, ...] = Field(default_factory=tuple)
    aggregate_note: str = AGGREGATE_NOTE

    def gate(self, name: GateName | str) -> GateResult:
        wanted = GateName(name) if not isinstance(name, GateName) else name
        for result in self.results:
            if result.name is wanted:
                return result
        raise EvaluationError(EvaluationErrorCode.GATE_UNKNOWN, f"gate not evaluated: {wanted.value}")

    @property
    def failed(self) -> tuple[str, ...]:
        return tuple(r.name.value for r in self.results if r.status is GateStatus.FAIL)


def _passes(result: MetricResult, threshold: float, direction: str) -> bool:
    if result.score is None:
        return False
    if direction == LOWER_IS_BETTER:
        return result.score <= threshold + 1e-9
    if direction == HIGHER_IS_BETTER:
        return result.score >= threshold - 1e-9
    raise EvaluationError(
        EvaluationErrorCode.GATE_UNKNOWN,
        f"unknown metric direction for {result.name}",
    )


def _security_gate(
    *,
    metrics: Mapping[str, MetricResult],
    thresholds: Mapping[str, float],
    required_metrics: Sequence[str],
    security_disagreements: Sequence[str],
    required: bool,
) -> GateResult:
    reasons: list[str] = []
    if security_disagreements:
        for item in tuple(security_disagreements)[:16]:
            reasons.append(f"disagreement:{item}")
    considered = [
        name
        for name in SECURITY_METRICS
        if name in thresholds or name in required_metrics
    ]
    if not considered:
        reasons.append("security-metrics-absent")
    for name in considered:
        result = metrics.get(name)
        if result is None:
            reasons.append(f"missing-metric:{name}")
            continue
        if result.score is None:
            reasons.append(f"not-computed:{name}")
            continue
        threshold = thresholds.get(name)
        if threshold is None:
            continue
        if not _passes(result, threshold, get_metric_definition(name).direction):
            reasons.append(f"below-threshold:{name}={result.score}<{threshold}")
    status = GateStatus.FAIL if reasons else GateStatus.PASS
    return GateResult(
        name=GateName.SECURITY_GATE,
        status=status,
        required=required,
        reasons=tuple(dict.fromkeys(reasons)),
        metrics=tuple(considered),
    )


def _correctness_gate(
    *,
    metrics: Mapping[str, MetricResult],
    thresholds: Mapping[str, float],
    required_metrics: Sequence[str],
    required: bool,
) -> GateResult:
    reasons: list[str] = []
    evaluated: list[str] = []
    for name in dict.fromkeys([*required_metrics, *thresholds]):
        get_metric_definition(name)
        evaluated.append(name)
        result = metrics.get(name)
        if result is None:
            reasons.append(f"missing-metric:{name}")
            continue
        if result.score is None:
            reasons.append(f"not-computed:{name}")
            continue
        threshold = thresholds.get(name)
        if threshold is None:
            continue
        if not _passes(result, threshold, get_metric_definition(name).direction):
            reasons.append(f"below-threshold:{name}={result.score}<{threshold}")
    return GateResult(
        name=GateName.CORRECTNESS_GATE,
        status=GateStatus.FAIL if reasons else GateStatus.PASS,
        required=required,
        reasons=tuple(dict.fromkeys(reasons)),
        metrics=tuple(evaluated),
    )


def _regression_gate(
    *,
    metrics: Mapping[str, MetricResult],
    baseline: Mapping[str, float],
    thresholds: Mapping[str, float],
    required: bool,
) -> GateResult:
    if not baseline:
        return GateResult(
            name=GateName.REGRESSION_GATE,
            status=GateStatus.NOT_EVALUATED,
            required=required,
            reasons=("no-baseline",),
        )
    reasons: list[str] = []
    evaluated: list[str] = []
    for name, floor in sorted(baseline.items()):
        get_metric_definition(name)
        evaluated.append(name)
        result = metrics.get(name)
        if result is None:
            reasons.append(f"missing-metric:{name}")
            continue
        if result.score is None:
            reasons.append(f"not-computed:{name}")
            continue
        if result.score + 1e-9 < floor:
            reasons.append(f"below-baseline:{name}={result.score}<{floor}")
        threshold = thresholds.get(name)
        if threshold is not None and not _passes(result, threshold, get_metric_definition(name).direction):
            reasons.append(f"below-threshold:{name}={result.score}<{threshold}")
    return GateResult(
        name=GateName.REGRESSION_GATE,
        status=GateStatus.FAIL if reasons else GateStatus.PASS,
        required=required,
        reasons=tuple(dict.fromkeys(reasons)),
        metrics=tuple(evaluated),
    )


def evaluate_gates(
    *,
    metrics: Mapping[str, MetricResult],
    thresholds: Mapping[str, float] | None = None,
    required_metrics: Sequence[str] = (),
    required_gates: Sequence[str] = (),
    security_disagreements: Sequence[str] = (),
    baseline: Mapping[str, float] | None = None,
) -> GateEvaluation:
    resolved_thresholds = {str(k): float(v) for k, v in (thresholds or {}).items()}
    required_names = [str(g) for g in required_gates]
    for name in required_names:
        GateName(name)  # unknown gate names fail closed
    wanted = set(required_names) | {g.value for g in GateName}

    results: list[GateResult] = []
    if GateName.SECURITY_GATE.value in wanted:
        results.append(
            _security_gate(
                metrics=metrics,
                thresholds=resolved_thresholds,
                required_metrics=[str(m) for m in required_metrics],
                security_disagreements=security_disagreements,
                required=GateName.SECURITY_GATE.value in required_names,
            )
        )
    if GateName.CORRECTNESS_GATE.value in wanted:
        results.append(
            _correctness_gate(
                metrics=metrics,
                thresholds=resolved_thresholds,
                required_metrics=[str(m) for m in required_metrics],
                required=GateName.CORRECTNESS_GATE.value in required_names,
            )
        )
    if GateName.REGRESSION_GATE.value in wanted:
        results.append(
            _regression_gate(
                metrics=metrics,
                baseline=dict(baseline or {}),
                thresholds=resolved_thresholds,
                required=GateName.REGRESSION_GATE.value in required_names,
            )
        )

    enforced: list[GateResult] = []
    for result in results:
        if result.required and result.status is GateStatus.NOT_EVALUATED:
            enforced.append(
                GateResult(
                    name=result.name,
                    status=GateStatus.FAIL,
                    required=True,
                    reasons=(*result.reasons, "required-gate-not-evaluated"),
                    metrics=result.metrics,
                )
            )
        else:
            enforced.append(result)
    statuses = [r.status for r in enforced]
    if any(status is GateStatus.FAIL for status in statuses):
        overall = GateStatus.FAIL
    elif statuses and all(status is GateStatus.PASS for status in statuses):
        overall = GateStatus.PASS
    else:
        overall = GateStatus.PARTIAL
    return GateEvaluation(
        overall=overall,
        results=tuple(enforced),
        thresholds=resolved_thresholds,
        required_metrics=tuple(str(m) for m in required_metrics),
        required_gates=tuple(required_names),
    )
