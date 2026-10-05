"""Bounded recovery actions.

Each action is a *named intent* only. Execution is performed by RecoveryManager
via injected callables within fixed bounds. No action may: escalate privilege,
mutate PolicyEngine, change Finding severity, rewrite Evidence, mutate source,
bypass verification, invent approval, or expand scope.
"""

from __future__ import annotations

from enum import Enum


class RecoveryAction(str, Enum):
    """Exhaustive action set."""

    RETRY = "RETRY"
    RECOMPUTE = "RECOMPUTE"
    REVALIDATE = "REVALIDATE"
    REFRESH_SNAPSHOT = "REFRESH_SNAPSHOT"
    REPLAN = "REPLAN"
    RELOAD_PROVIDER = "RELOAD_PROVIDER"
    RELOAD_RESOURCE = "RELOAD_RESOURCE"
    QUARANTINE = "QUARANTINE"
    RESUME_FROM_CHECKPOINT = "RESUME_FROM_CHECKPOINT"
    FAIL_CLOSED = "FAIL_CLOSED"


#: Actions that re-execute work and therefore consume the retry budget.
RETRY_LIKE_ACTIONS: frozenset[RecoveryAction] = frozenset(
    {
        RecoveryAction.RETRY,
        RecoveryAction.RECOMPUTE,
        RecoveryAction.REVALIDATE,
        RecoveryAction.REFRESH_SNAPSHOT,
        RecoveryAction.REPLAN,
        RecoveryAction.RELOAD_PROVIDER,
        RecoveryAction.RELOAD_RESOURCE,
        RecoveryAction.RESUME_FROM_CHECKPOINT,
    }
)

#: Terminal actions that never consume retry budget and never re-execute work.
TERMINAL_ACTIONS: frozenset[RecoveryAction] = frozenset(
    {
        RecoveryAction.QUARANTINE,
        RecoveryAction.FAIL_CLOSED,
    }
)
