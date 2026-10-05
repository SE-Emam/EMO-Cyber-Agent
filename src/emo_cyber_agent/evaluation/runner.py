"""Evaluation runner — POST-RC-013.

The runner is the only place that sequences a run:

    blind case → prepare → authority snapshot → invoke → authority snapshot
    → mark executed → release ground truth → observations → oracles
    → metrics → gates → run

Determinism is structural: cases run in sorted order, nothing random
reaches an identity digest, and ``run_id`` is derived from the identity
digest itself. Repeated executions (``repeat=N``) must agree before the
DETERMINISM metric reports anything.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.evaluation.cases import BlindEvaluationCase, EvaluationCase
from emo_cyber_agent.evaluation.datasets import BlindDatasetProvider, EvaluationDataset
from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.gates import GateEvaluation, evaluate_gates
from emo_cyber_agent.evaluation.metrics import (
    ALL_METRIC_NAMES,
    DeterminismScore,
    MetricContext,
    MetricResult,
    compute_metrics,
)
from emo_cyber_agent.evaluation.oracle import (
    Oracle,
    OracleContext,
    OracleJudgment,
    default_oracles,
    security_disagreements,
    select_oracles,
)
from emo_cyber_agent.evaluation.reproducibility import environment_capture
from emo_cyber_agent.evaluation.spec import (
    AuthorityDiff,
    EvaluationEvent,
    EvaluationObservation,
    EvaluationStage,
    RunStatus,
    diff_authority,
    evaluation_digest,
)
from emo_cyber_agent.evaluation.sut import SUTAdapter, SUTResult

__all__ = ["EvaluationRun", "EvaluationRunner", "DEFAULT_METRIC_SELECTION"]

DEFAULT_METRIC_SELECTION: tuple[str, ...] = ALL_METRIC_NAMES


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvaluationRun(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str = Field(..., min_length=1, max_length=64)
    dataset_id: str = Field(..., min_length=1, max_length=64)
    dataset_fingerprint: str = Field(..., min_length=8, max_length=128)
    sut_id: str = Field(..., min_length=1, max_length=64)
    sut_version: str = Field(..., min_length=1, max_length=32)
    status: RunStatus = RunStatus.COMPLETED
    started_at: str = Field(default_factory=_now)
    completed_at: str = Field(default_factory=_now)
    case_ids: tuple[str, ...] = ()
    events: tuple[EvaluationEvent, ...] = ()
    observations: tuple[EvaluationObservation, ...] = ()
    judgments: tuple[OracleJudgment, ...] = ()
    metrics: dict[str, MetricResult] = Field(default_factory=dict)
    gates: GateEvaluation
    counts: dict[str, int] = Field(default_factory=dict)
    determinism: DeterminismScore = DeterminismScore()
    environment: dict[str, str] = Field(default_factory=dict)
    identity_digest: str = Field(..., min_length=8, max_length=128)
    volatile_fields: tuple[str, ...] = (
        "run_id",
        "started_at",
        "completed_at",
        "environment",
        "events",
    )

    def identity_payload(self) -> dict[str, Any]:
        """Everything that must repeat across identical executions."""
        return {
            "dataset_id": self.dataset_id,
            "dataset_fingerprint": self.dataset_fingerprint,
            "sut_id": self.sut_id,
            "sut_version": self.sut_version,
            "status": self.status.value,
            "case_ids": list(self.case_ids),
            "observations": [obs.identity_digest for obs in self.observations],
            "judgments": [j.identity_digest for j in self.judgments],
            "metrics": {
                name: result.model_dump(mode="json") for name, result in sorted(self.metrics.items())
            },
            "gates": self.gates.model_dump(mode="json"),
            "counts": dict(sorted(self.counts.items())),
            "determinism": self.determinism.model_dump(mode="json"),
        }

    @property
    def security_disagreements(self) -> tuple[str, ...]:
        return security_disagreements(self.judgments)

    @property
    def failures(self) -> tuple[str, ...]:
        return tuple(
            f"{r.name.value}:{reason}"
            for r in self.gates.results
            if r.status.value == "fail"
            for reason in r.reasons
        )


class EvaluationRunner:
    """Runs a dataset against one system under test."""

    def __init__(
        self,
        *,
        dataset: EvaluationDataset,
        sut: SUTAdapter,
        provider: BlindDatasetProvider | None = None,
        oracles: Iterable[Oracle] | Iterable[str] | None = None,
        metrics: Sequence[str] | None = None,
        baseline: Mapping[str, float] | None = None,
    ) -> None:
        if provider is not None and provider.dataset is not dataset:
            raise EvaluationError(
                EvaluationErrorCode.INVALID_DATASET,
                "provider was built for a different dataset",
            )
        self._dataset = dataset
        self._sut = sut
        self._provider = provider
        self._oracles = self._resolve_oracles(oracles)
        thresholds = dataset.manifest.thresholds
        required = dataset.manifest.required_metrics
        resolved_baseline = dict(baseline if baseline is not None else dataset.manifest.baseline)
        wanted = set(metrics or DEFAULT_METRIC_SELECTION)
        wanted |= set(thresholds) | set(required) | set(resolved_baseline)
        unknown = sorted(name for name in wanted if name not in set(DEFAULT_METRIC_SELECTION))
        if unknown:
            raise EvaluationError(
                EvaluationErrorCode.METRIC_UNKNOWN,
                f"metric not in the evaluation registry: {unknown[0]}",
            )
        self._metric_names = tuple(sorted(wanted))
        self._baseline = resolved_baseline

    @staticmethod
    def _resolve_oracles(oracles: Iterable[Oracle] | Iterable[str] | None) -> tuple[Oracle, ...]:
        if oracles is None:
            return default_oracles()
        items = list(oracles)
        if not items:
            return default_oracles()
        if isinstance(items[0], Oracle):
            return tuple(items)  # type: ignore[return-value]
        return select_oracles(str(name) for name in items)

    def run(
        self,
        *,
        split: str | None = None,
        tracks: Sequence[str] | None = None,
        stages: Sequence[str] | None = None,
        sections: Sequence[str] | None = None,
        case_ids: Sequence[str] | None = None,
        repeat: int = 1,
    ) -> EvaluationRun:
        if repeat < 1:
            raise EvaluationError(EvaluationErrorCode.PROTOCOL_ERROR, "repeat must be >= 1")
        selected = self._dataset.select(
            split=split,
            tracks=tracks,
            stages=stages,
            sections=sections,
            case_ids=case_ids,
        )
        if not selected:
            raise EvaluationError(
                EvaluationErrorCode.DATASET_EMPTY,
                "selection produced no cases",
            )
        provider = self._provider or BlindDatasetProvider(self._dataset)
        started_at = _now()
        executions: list[
            tuple[
                tuple[EvaluationEvent, ...],
                tuple[EvaluationObservation, ...],
                tuple[OracleJudgment, ...],
                int,
                int,
            ]
        ] = []
        for index in range(repeat):
            executions.append(self._execute_once(selected, provider, capture_events=index == 0))
        event_stream, observations, judgments, ok_count, failed_count = executions[0]
        exec_digests = tuple(
            evaluation_digest(
                {
                    "observations": [obs.identity_digest for obs in entry[1]],
                    "judgments": [j.identity_digest for j in entry[2]],
                }
            )
            for entry in executions
        )
        determinism = DeterminismScore(
            repeat_count=repeat,
            matched=len(set(exec_digests)) == 1,
            digests=tuple(dict.fromkeys(exec_digests)),
        )
        context = MetricContext(
            judgments=judgments, observations=observations, determinism=determinism
        )
        metric_results = compute_metrics(self._metric_names, context)
        disagreements = security_disagreements(judgments)
        manifest = self._dataset.manifest
        gates = evaluate_gates(
            metrics=metric_results,
            thresholds=manifest.thresholds,
            required_metrics=manifest.required_metrics,
            required_gates=manifest.required_gates,
            security_disagreements=disagreements,
            baseline=self._baseline,
        )
        counts = {
            "cases": len(selected),
            "cases_ok": ok_count,
            "cases_failed": failed_count,
            "observations": len(observations),
            "judgments": len(judgments),
            "events": len(event_stream),
            "security_disagreements": len(disagreements),
            "tracks": len({case.track.value for case in selected}),
            "stages": len({case.stage.value for case in selected}),
        }
        status = RunStatus.COMPLETED if failed_count == 0 else RunStatus.PARTIAL
        identity = evaluation_digest(
            {
                "dataset_id": self._dataset.dataset_id,
                "dataset_fingerprint": self._dataset.fingerprint,
                "sut_id": self._sut.sut_id,
                "sut_version": self._sut.sut_version,
                "status": status.value,
                "case_ids": [case.case_id for case in selected],
                "observations": [obs.identity_digest for obs in observations],
                "judgments": [j.identity_digest for j in judgments],
                "metrics": {name: r.model_dump(mode="json") for name, r in sorted(metric_results.items())},
                "gates": gates.model_dump(mode="json"),
                "counts": dict(sorted(counts.items())),
                "determinism": determinism.model_dump(mode="json"),
            }
        )
        run = EvaluationRun(
            run_id=f"run-{identity[:16]}",
            dataset_id=self._dataset.dataset_id,
            dataset_fingerprint=self._dataset.fingerprint,
            sut_id=self._sut.sut_id,
            sut_version=self._sut.sut_version,
            status=status,
            started_at=started_at,
            completed_at=_now(),
            case_ids=tuple(case.case_id for case in selected),
            events=event_stream,
            observations=observations,
            judgments=judgments,
            metrics=metric_results,
            gates=gates,
            counts=counts,
            determinism=determinism,
            environment=environment_capture(),
            identity_digest=identity,
        )
        if run.identity_digest != identity:  # pragma: no cover - defensive
            raise EvaluationError(
                EvaluationErrorCode.INTERNAL,
                "run identity payload diverged from computed digest",
            )
        return run

    # ------------------------------------------------------------------
    def _execute_once(
        self,
        selected: Sequence[EvaluationCase],
        provider: BlindDatasetProvider,
        *,
        capture_events: bool,
    ) -> tuple[
        tuple[EvaluationEvent, ...],
        tuple[EvaluationObservation, ...],
        tuple[OracleJudgment, ...],
        int,
        int,
    ]:
        """Execute every selected case once, in sorted order.

        Cases are already sorted by the dataset loader; the order is the
        execution order and therefore part of the run identity."""
        events: list[EvaluationEvent] = []
        observations: list[EvaluationObservation] = []
        judgments: list[OracleJudgment] = []
        failed = 0
        for index, case in enumerate(selected):
            case_obs, case_judgments = self._run_case(
                case,
                provider,
                sequence_base=index * 4,
                events=events if capture_events else None,
            )
            observations.extend(case_obs)
            judgments.extend(case_judgments)
            if any(obs.payload.get("ok") is False for obs in case_obs):
                failed += 1
        return (
            tuple(events),
            tuple(observations),
            tuple(judgments),
            len(selected) - failed,
            failed,
        )

    def _run_case(
        self,
        case: EvaluationCase,
        provider: BlindDatasetProvider,
        *,
        sequence_base: int,
        events: list[EvaluationEvent] | None,
    ) -> tuple[list[EvaluationObservation], list[OracleJudgment]]:
        blind: BlindEvaluationCase = provider.blind_case(case.case_id)
        self._sut.prepare_case(blind)
        before = self._sut.authority_probe()
        try:
            result = self._sut.invoke(blind)
        except EvaluationError as exc:
            result = SUTResult(
                sut_id=self._sut.sut_id,
                sut_version=self._sut.sut_version,
                case_id=case.case_id,
                stage=case.stage.value,
                kind=case.scenario.kind,
                ok=False,
                error_code=exc.code.value,
                error_message=exc.message,
            )
        except Exception as exc:  # noqa: BLE001 - runner boundary
            from emo_cyber_agent.core.repository import redact_credentials

            result = SUTResult(
                sut_id=self._sut.sut_id,
                sut_version=self._sut.sut_version,
                case_id=case.case_id,
                stage=case.stage.value,
                kind=case.scenario.kind,
                ok=False,
                error_code=EvaluationErrorCode.ADAPTER_ERROR.value,
                error_message=redact_credentials(f"{type(exc).__name__}: {exc}")[:400],
            )
        after = self._sut.authority_probe()
        provider.mark_executed(case.case_id)
        records = provider.ground_time_for(case.case_id)
        if events is not None:
            events.append(
                EvaluationEvent(
                    case_id=case.case_id,
                    stage=EvaluationStage.INPUT_FACTS,
                    kind="invoked",
                    sequence=sequence_base,
                    payload={"ok": result.ok, "kind": case.scenario.kind},
                )
            )
        observations = list(self._sut.collect_observations(result))
        diff: AuthorityDiff | None = None
        if before is not None and after is not None:
            diff = diff_authority(before, after)
            observations.append(
                EvaluationObservation(
                    case_id=case.case_id,
                    stage=EvaluationStage.AUTHORITY,
                    kind="authority_diff",
                    payload={"authority_diff": diff.model_dump(mode="json")},
                )
            )
        if events is not None:
            events.append(
                EvaluationEvent(
                    case_id=case.case_id,
                    stage=EvaluationStage.EVIDENCE,
                    kind="observed",
                    sequence=sequence_base + 1,
                    payload={"observations": len(observations)},
                )
            )
        effective = case if records == case.ground_truth else case.with_ground_truth(records)
        context = OracleContext(
            case=effective,
            result=result,
            observations=tuple(observations),
            authority_diff=diff,
        )
        judgments: list[OracleJudgment] = []
        for oracle in self._oracles:
            judgments.extend(oracle.evaluate(context))
        if events is not None:
            events.append(
                EvaluationEvent(
                    case_id=case.case_id,
                    stage=EvaluationStage.HYPOTHESES,
                    kind="judged",
                    sequence=sequence_base + 2,
                    payload={"judgments": len(judgments)},
                )
            )
            events.append(
                EvaluationEvent(
                    case_id=case.case_id,
                    stage=EvaluationStage.AUTHORITY,
                    kind="authority_checked",
                    sequence=sequence_base + 3,
                    payload={"state": diff.state if diff else "not-applicable"},
                )
            )
        return observations, judgments
