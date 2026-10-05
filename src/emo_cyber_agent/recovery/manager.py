"""RecoveryManager: classify + decide + execute bounded action.

Pipeline: classify(failure) -> decide(classification) -> execute(action)
strictly within the policy budget. The manager:

- never escalates privilege, mutates PolicyEngine, changes Finding severity,
  rewrites Evidence, mutates source, bypasses verification, invents approval,
  expands scope, or reuses cross-audit context;
- refuses cross-audit recovery (ScopeViolationError);
- treats POLICY_DENIED / INTEGRITY_FAILURE as immediate FAIL_CLOSED with
  zero attempts;
- enforces MAX_RECOVERY_ATTEMPTS (no infinite loops);
- passes findings/evidence through read-only snapshots only.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .actions import TERMINAL_ACTIONS, RecoveryAction
from .classification import FailureClassification, classify
from .policy import MAX_RECOVERY_ATTEMPTS, decide
from .reporting import RecoveryAttemptRecord, RecoveryReport, build_report

#: Outcome constants (DATA strings, not instructions).
OUTCOME_RECOVERED = "RECOVERED"
OUTCOME_QUARANTINED = "QUARANTINED"
OUTCOME_FAILED_CLOSED = "FAILED_CLOSED"
OUTCOME_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"

#: Recovery never touches these keys even if present on inputs.
_FORBIDDEN_MUTATION_TARGETS: frozenset[str] = frozenset(
    {
        "policy_engine",
        "findings",
        "evidence",
        "severity",
        "source",
        "approvals",
        "scope",
        "privileges",
    }
)


@dataclass(frozen=True)
class RecoveryRequest:
    """Immutable recovery request. Findings/evidence carried read-only."""

    audit_id: str
    failure: Any  # classification token or FailureClassification
    checkpoint_audit_id: str | None = None  # must equal audit_id when set
    context: Mapping[str, Any] | None = None  # read-only snapshot; never mutated


def _snapshot_context(context: Mapping[str, Any] | None) -> dict[str, Any]:
    if context is None:
        return {}
    if not isinstance(context, Mapping):
        from .errors import RecoveryError

        raise RecoveryError(f"context must be a mapping, got {type(context).__name__}")
    return dict(context)  # shallow copy: manager never mutates caller state


class RecoveryManager:
    """Stateless executor of bounded recovery decisions."""

    def __init__(self, *, executor: Callable[[RecoveryAction, dict[str, Any]], bool] | None = None) -> None:
        # Default executor performs no work and reports failure (fail-closed).
        self._executor = executor if executor is not None else (lambda _a, _c: False)

    @property
    def executor(self) -> Callable[[RecoveryAction, dict[str, Any]], bool]:
        return self._executor

    def recover(self, request: RecoveryRequest) -> RecoveryReport:
        """Classify, decide, and execute within bounds. Always returns a report."""
        from .errors import ScopeViolationError

        if not isinstance(request.audit_id, str) or not request.audit_id.strip():
            from .errors import RecoveryError

            raise RecoveryError("audit_id must be a non-empty string")
        if request.checkpoint_audit_id is not None and request.checkpoint_audit_id != request.audit_id:
            raise ScopeViolationError(
                f"Cross-audit recovery rejected: request audit {request.audit_id!r} "
                f"!= checkpoint audit {request.checkpoint_audit_id!r}"
            )
        classification = self.classify_failure(request.failure)
        decision = decide(classification)
        ctx = _snapshot_context(request.context)

        if decision.action in TERMINAL_ACTIONS or decision.max_attempts <= 0:
            outcome = (
                OUTCOME_QUARANTINED
                if decision.action == RecoveryAction.QUARANTINE
                else OUTCOME_FAILED_CLOSED
            )
            return build_report(
                audit_id=request.audit_id,
                classification=classification,
                action=decision.action,
                outcome=outcome,
                records=(),
                detail=f"Terminal action {decision.action.value} for {classification.value}; no attempts made.",
            )

        records: list[RecoveryAttemptRecord] = []
        budget = min(decision.max_attempts, MAX_RECOVERY_ATTEMPTS)
        for attempt in range(1, budget + 1):
            succeeded = bool(self._executor(decision.action, dict(ctx)))
            records.append(
                RecoveryAttemptRecord(
                    attempt=attempt,
                    action=decision.action.value,
                    succeeded=succeeded,
                    detail="succeeded" if succeeded else "executor reported failure",
                )
            )
            if succeeded:
                return build_report(
                    audit_id=request.audit_id,
                    classification=classification,
                    action=decision.action,
                    outcome=OUTCOME_RECOVERED,
                    records=records,
                )
        return build_report(
            audit_id=request.audit_id,
            classification=classification,
            action=decision.action,
            outcome=OUTCOME_BUDGET_EXHAUSTED,
            records=records,
            detail=f"Budget exhausted after {len(records)} attempt(s); failing closed.",
        )

    @staticmethod
    def classify_failure(failure: Any) -> FailureClassification:
        """Classify a failure token. Unknown input raises ClassificationError."""
        return classify(failure)

    @staticmethod
    def forbidden_mutation_targets() -> frozenset[str]:
        """Names recovery must never mutate (contract witness for tests)."""
        return _FORBIDDEN_MUTATION_TARGETS
