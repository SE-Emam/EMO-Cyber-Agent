"""Classification -> action policy mapping (bounded, deterministic).

The policy is a pure function: (classification) -> (action, max_attempts).
It grants no capability and performs no I/O. Hard rules:

- POLICY_DENIED and INTEGRITY_FAILURE always map to FAIL_CLOSED. Never retry.
- SCOPE_MISMATCH maps to QUARANTINE (isolate), never retry/expand.
- UNKNOWN maps to FAIL_CLOSED.
- Everything else maps to a bounded retry-like action with a fixed budget.
"""

from __future__ import annotations

from dataclasses import dataclass

from .actions import RecoveryAction
from .classification import FailureClassification

#: Hard upper bound on attempts for any retry-like recovery. No infinite loops.
MAX_RECOVERY_ATTEMPTS: int = 3

#: Classifications that must never be retried under any circumstance.
NEVER_RETRY: frozenset[FailureClassification] = frozenset(
    {
        FailureClassification.POLICY_DENIED,
        FailureClassification.INTEGRITY_FAILURE,
        FailureClassification.SCOPE_MISMATCH,
        FailureClassification.UNKNOWN,
    }
)


@dataclass(frozen=True)
class RecoveryDecision:
    """Immutable policy decision: what to do and how many times at most."""

    classification: FailureClassification
    action: RecoveryAction
    max_attempts: int
    retryable: bool


_POLICY_TABLE: dict[FailureClassification, tuple[RecoveryAction, int, bool]] = {
    FailureClassification.TRANSIENT: (RecoveryAction.RETRY, MAX_RECOVERY_ATTEMPTS, True),
    FailureClassification.STALE_CONTEXT: (RecoveryAction.REFRESH_SNAPSHOT, 1, True),
    FailureClassification.PROVIDER_UNAVAILABLE: (RecoveryAction.RELOAD_PROVIDER, 2, True),
    FailureClassification.MALFORMED_OUTPUT: (RecoveryAction.REVALIDATE, 2, True),
    FailureClassification.RESOURCE_EXHAUSTED: (RecoveryAction.RELOAD_RESOURCE, 1, True),
    FailureClassification.DEPENDENCY_MISMATCH: (RecoveryAction.RECOMPUTE, 1, True),
    FailureClassification.SCOPE_MISMATCH: (RecoveryAction.QUARANTINE, 0, False),
    FailureClassification.POLICY_DENIED: (RecoveryAction.FAIL_CLOSED, 0, False),
    FailureClassification.INTEGRITY_FAILURE: (RecoveryAction.FAIL_CLOSED, 0, False),
    FailureClassification.UNKNOWN: (RecoveryAction.FAIL_CLOSED, 0, False),
}


def decide(classification: FailureClassification) -> RecoveryDecision:
    """Return the bounded recovery decision for *classification*.

    Raises:
        ClassificationError: if *classification* is not a known member.
    """
    from .errors import ClassificationError

    if not isinstance(classification, FailureClassification):
        raise ClassificationError(f"Unknown failure classification: {classification!r}")
    try:
        action, attempts, retryable = _POLICY_TABLE[classification]
    except KeyError as exc:
        raise ClassificationError(f"No policy for classification: {classification!r}") from exc
    if classification in NEVER_RETRY and (retryable or attempts != 0):
        # Defense in depth: the table must never grant retries to fail-closed classes.
        raise ClassificationError(f"Policy table violates NEVER_RETRY for {classification!r}")
    return RecoveryDecision(
        classification=classification,
        action=action,
        max_attempts=attempts,
        retryable=retryable,
    )


def policy_table() -> dict[str, dict[str, object]]:
    """Return a JSON-serializable snapshot of the classification -> action table."""
    return {
        c.value: {"action": a.value, "max_attempts": n, "retryable": r}
        for c, (a, n, r) in _POLICY_TABLE.items()
    }
