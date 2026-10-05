"""Recovery reporting: structured DATA, never instructions.

A RecoveryReport records what happened (classification, action, attempts,
outcome) as plain data. It contains no instructions, no remediation commands,
and no authority claims. Downstream consumers must treat reports as data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .actions import RecoveryAction
from .classification import FailureClassification


@dataclass(frozen=True)
class RecoveryAttemptRecord:
    """DATA record of a single bounded attempt."""

    attempt: int  # 1-based
    action: str
    succeeded: bool
    detail: str = ""


@dataclass(frozen=True)
class RecoveryReport:
    """Immutable DATA summary of a recovery run."""

    audit_id: str
    classification: str
    action: str
    outcome: str  # "RECOVERED" | "QUARANTINED" | "FAILED_CLOSED" | "BUDGET_EXHAUSTED"
    attempts_made: int
    attempts: tuple[RecoveryAttemptRecord, ...] = ()
    detail: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "recovery_report",
            "audit_id": self.audit_id,
            "classification": self.classification,
            "action": self.action,
            "outcome": self.outcome,
            "attempts_made": self.attempts_made,
            "attempts": [
                {
                    "attempt": a.attempt,
                    "action": a.action,
                    "succeeded": a.succeeded,
                    "detail": a.detail,
                }
                for a in self.attempts
            ],
            "detail": self.detail,
            "created_at": self.created_at,
        }


def build_report(
    *,
    audit_id: str,
    classification: FailureClassification,
    action: RecoveryAction,
    outcome: str,
    records: list[RecoveryAttemptRecord] | tuple[RecoveryAttemptRecord, ...] = (),
    detail: str = "",
) -> RecoveryReport:
    """Build an immutable DATA report. Validates enums; never emits instructions."""
    from .errors import RecoveryError

    if outcome not in ("RECOVERED", "QUARANTINED", "FAILED_CLOSED", "BUDGET_EXHAUSTED"):
        raise RecoveryError(f"Invalid recovery outcome: {outcome!r}")
    if not isinstance(audit_id, str) or not audit_id.strip():
        raise RecoveryError("audit_id must be a non-empty string")
    rows = tuple(records)
    return RecoveryReport(
        audit_id=audit_id,
        classification=classification.value,
        action=action.value,
        outcome=outcome,
        attempts_made=len(rows),
        attempts=rows,
        detail=str(detail),
    )
