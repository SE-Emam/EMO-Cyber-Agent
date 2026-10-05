"""Reproducibility — POST-RC-013.

A run is reproducible when its identity digest — everything that is not a
timestamp or an environment fact — repeats exactly. ``run_id`` is derived
from that digest, so two identical executions cannot claim different
identities, and a changed one cannot keep the same id.

Environment capture uses ``platform``/``sys`` only: the evaluation layer
never reads host configuration.
"""

from __future__ import annotations

import platform
import sys
from typing import TYPE_CHECKING, Sequence

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.spec import evaluation_digest

if TYPE_CHECKING:  # pragma: no cover - typing only
    from emo_cyber_agent.evaluation.runner import EvaluationRun

__all__ = [
    "environment_capture",
    "identity_digest_of",
    "DeterminismReport",
    "verify_determinism",
    "assert_deterministic",
    "VOLATILE_RUN_FIELDS",
]

VOLATILE_RUN_FIELDS: tuple[str, ...] = ("run_id", "started_at", "completed_at", "environment")


def environment_capture() -> dict[str, str]:
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "executable": sys.executable.split("/")[-1] if sys.executable else "",
    }


def identity_digest_of(run: "EvaluationRun") -> str:
    return run.identity_digest


class DeterminismReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    repeat_count: int = Field(default=0, ge=0)
    deterministic: bool = False
    digests: tuple[str, ...] = ()
    first_run_id: str = ""

    @property
    def digest(self) -> str:
        return evaluation_digest({"digests": list(self.digests), "repeat": self.repeat_count})


def verify_determinism(runs: Sequence["EvaluationRun | str"]) -> DeterminismReport:
    digests: list[str] = []
    run_ids: list[str] = []
    for entry in runs:
        if isinstance(entry, str):
            digests.append(entry)
        else:
            digests.append(entry.identity_digest)
            run_ids.append(entry.run_id)
    unique = tuple(dict.fromkeys(digests))
    return DeterminismReport(
        repeat_count=len(digests),
        deterministic=bool(digests) and len(unique) == 1,
        digests=unique,
        first_run_id=run_ids[0] if run_ids else "",
    )


def assert_deterministic(runs: Sequence["EvaluationRun | str"]) -> DeterminismReport:
    report = verify_determinism(runs)
    if not report.deterministic:
        raise EvaluationError(
            EvaluationErrorCode.NON_DETERMINISTIC,
            f"identity digests differ across {report.repeat_count} runs: {len(report.digests)} variants",
        )
    return report
