"""Evaluation reporting and archiving — POST-RC-013.

A report is derived from a run, never from a narrative: gate outcomes,
metric denominators, and the identity digest travel together, and the
report states in words that aggregate scores cannot override a failed gate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Sequence

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.gates import GateResult
from emo_cyber_agent.evaluation.runner import EvaluationRun
from emo_cyber_agent.evaluation.spec import EVALUATION_VERSION, GateStatus, utc_now

__all__ = [
    "EvaluationReport",
    "build_report",
    "to_json",
    "to_markdown",
    "EvaluationArchive",
]

_MAX_LIMITATIONS = 24


class ReportMetric(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    score: float | None = None
    count: int = 0
    denominator: int = 0
    coverage: float = 0.0
    unknown: int = 0
    inconclusive: int = 0
    blocked: int = 0
    confidence: str = ""
    notes: tuple[str, ...] = ()


class ReportSUT(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sut_id: str
    sut_version: str


class EvaluationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str = Field(..., min_length=1, max_length=64)
    run_id: str = Field(..., min_length=1, max_length=64)
    dataset_id: str = Field(..., min_length=1, max_length=64)
    dataset_fingerprint: str = Field(..., min_length=8, max_length=128)
    sut: ReportSUT
    evaluator_version: str = Field(default=EVALUATION_VERSION, min_length=1, max_length=32)
    generated_at: str = Field(default_factory=utc_now)
    run_status: str = Field(..., min_length=1, max_length=32)
    overall_gate: str = Field(..., min_length=1, max_length=32)
    aggregate_note: str = Field(..., min_length=8, max_length=300)
    gates: tuple[GateResult, ...] = ()
    metrics: tuple[ReportMetric, ...] = ()
    counts: dict[str, int] = Field(default_factory=dict)
    determinism_repeats: int = Field(default=1, ge=1)
    determinism_matched: bool = False
    identity_digest: str = Field(..., min_length=8, max_length=128)
    limitations: tuple[str, ...] = Field(default_factory=tuple, max_length=_MAX_LIMITATIONS)


def build_report(run: EvaluationRun, *, limitations: Iterable[str] = ()) -> EvaluationReport:
    if run.gates.overall is GateStatus.FAIL and not limitations:
        raised = [
            reason
            for gate in run.gates.results
            if gate.status is GateStatus.FAIL
            for reason in gate.reasons
        ]
        limitations = [*raised[: _MAX_LIMITATIONS - 1], "aggregate scores do not override a failed gate"]
    cleaned = tuple(dict.fromkeys(str(item)[:200] for item in limitations if str(item).strip()))
    return EvaluationReport(
        report_id=f"rep-{run.identity_digest[:16]}",
        run_id=run.run_id,
        dataset_id=run.dataset_id,
        dataset_fingerprint=run.dataset_fingerprint,
        sut=ReportSUT(sut_id=run.sut_id, sut_version=run.sut_version),
        run_status=run.status.value,
        overall_gate=run.gates.overall.value,
        aggregate_note=run.gates.aggregate_note,
        gates=run.gates.results,
        metrics=tuple(
            ReportMetric(
                name=result.name,
                score=result.score,
                count=result.count,
                denominator=result.denominator,
                coverage=result.coverage,
                unknown=result.unknown,
                inconclusive=result.inconclusive,
                blocked=result.blocked,
                confidence=result.confidence,
                notes=result.notes,
            )
            for result in sorted(run.metrics.values(), key=lambda item: item.name)
        ),
        counts=dict(sorted(run.counts.items())),
        determinism_repeats=run.determinism.repeat_count,
        determinism_matched=run.determinism.matched,
        identity_digest=run.identity_digest,
        limitations=cleaned[:_MAX_LIMITATIONS],
    )


def to_json(report: EvaluationReport, *, indent: int | None = 2) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=indent, sort_keys=True, default=str)


def _fmt_score(metric: ReportMetric) -> str:
    if metric.score is None:
        return "n/a"
    return f"{metric.score:.3f}"


def to_markdown(report: EvaluationReport) -> str:
    lines: list[str] = [
        "# Evaluation report",
        "",
        f"- report: `{report.report_id}`",
        f"- run: `{report.run_id}`",
        f"- dataset: `{report.dataset_id}` (`{report.dataset_fingerprint[:12]}`)",
        f"- system under test: `{report.sut.sut_id}` {report.sut.sut_version}",
        f"- run status: **{report.run_status}**",
        f"- overall gate: **{report.overall_gate.upper()}**",
        "",
        f"> {report.aggregate_note}",
        "",
        "## Gates",
        "",
        "| gate | status | required | reasons |",
        "| --- | --- | --- | --- |",
    ]
    for gate in report.gates:
        reasons = ", ".join(gate.reasons[:4]) or "-"
        lines.append(
            f"| {gate.name.value} | {gate.status.value} | {'yes' if gate.required else 'no'} | {reasons} |"
        )
    lines += ["", "## Metrics", "", "| metric | score | coverage | denominator | confidence |", "| --- | --- | --- | --- | --- |"]
    for metric in report.metrics:
        lines.append(
            f"| {metric.name} | {_fmt_score(metric)} | {metric.coverage:.2f} | "
            f"{metric.denominator} | {metric.confidence or '-'} |"
        )
    lines += ["", "## Counts", ""]
    for key, value in report.counts.items():
        lines.append(f"- {key}: {value}")
    lines += [
        "",
        f"- determinism repeats: {report.determinism_repeats}",
        f"- determinism matched: {'yes' if report.determinism_matched else 'no'}",
        f"- identity digest: `{report.identity_digest}`",
        "",
    ]
    if report.limitations:
        lines.append("## Limitations")
        lines.append("")
        for item in report.limitations:
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines)


class EvaluationArchive:
    """Filesystem archive for runs and reports (JSON only, no database)."""

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)

    @property
    def directory(self) -> Path:
        return self._directory

    def save(self, run: EvaluationRun, report: EvaluationReport | None = None) -> tuple[Path, Path]:
        self._directory.mkdir(parents=True, exist_ok=True)
        report = report or build_report(run)
        run_path = self._directory / f"{run.run_id}.run.json"
        report_path = self._directory / f"{run.run_id}.report.json"
        run_path.write_text(run.model_dump_json(indent=2), encoding="utf-8")
        report_path.write_text(to_json(report), encoding="utf-8")
        return run_path, report_path

    def list_runs(self) -> tuple[str, ...]:
        if not self._directory.is_dir():
            return ()
        return tuple(sorted(p.name[: -len(".run.json")] for p in self._directory.glob("*.run.json")))

    def load(self, run_id: str) -> tuple[EvaluationRun, EvaluationReport]:
        run_path = self._directory / f"{run_id}.run.json"
        report_path = self._directory / f"{run_id}.report.json"
        if not run_path.is_file() or not report_path.is_file():
            raise EvaluationError(EvaluationErrorCode.RUN_NOT_FOUND, f"archived run not found: {run_id}")
        try:
            run = EvaluationRun.model_validate_json(run_path.read_text(encoding="utf-8"))
            report = EvaluationReport.model_validate_json(report_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise EvaluationError(
                EvaluationErrorCode.REPORT_INVALID,
                f"archived run unreadable: {run_id}: {exc}",
            ) from exc
        return run, report

    def save_many(
        self,
        runs: Sequence[EvaluationRun],
        reports: Sequence[EvaluationReport] | None = None,
    ) -> tuple[Path, ...]:
        pairs: list[tuple[Path, Path]] = []
        for index, run in enumerate(runs):
            report = reports[index] if reports and index < len(reports) else None
            pairs.append(self.save(run, report))
        return tuple(path for pair in pairs for path in pair)
