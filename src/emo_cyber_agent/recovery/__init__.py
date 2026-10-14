"""Bounded recovery contracts for EMO-Cyber-Agent.

Self-correction here means deterministic validation / recompute / replan /
bounded retry / model re-proposal within fixed bounds ONLY. Recovery NEVER:
escalates privilege, mutates PolicyEngine, changes Finding severity, rewrites
Evidence, mutates source, bypasses verification, invents approval, expands
scope, or reuses cross-audit context.
"""

from .actions import RETRY_LIKE_ACTIONS, TERMINAL_ACTIONS, RecoveryAction
from .checkpoint import Checkpoint, capture, describe, restore
from .classification import FailureClassification, classify, classify_or_unknown
from .errors import (
    ActionExecutionError,
    BudgetExhaustedError,
    CheckpointError,
    ClassificationError,
    IntegrityFailureError,
    PolicyDeniedError,
    RecoveryError,
    ScopeViolationError,
)
from .manager import (
    OUTCOME_BUDGET_EXHAUSTED,
    OUTCOME_FAILED_CLOSED,
    OUTCOME_QUARANTINED,
    OUTCOME_RECOVERED,
    RecoveryManager,
    RecoveryRequest,
)
from .policy import (
    MAX_RECOVERY_ATTEMPTS,
    NEVER_RETRY,
    RecoveryDecision,
    decide,
    policy_table,
)
from .reporting import (
    RecoveryAttemptRecord,
    RecoveryReport,
    build_report,
)

__all__ = [
    "MAX_RECOVERY_ATTEMPTS",
    "NEVER_RETRY",
    "OUTCOME_BUDGET_EXHAUSTED",
    "OUTCOME_FAILED_CLOSED",
    "OUTCOME_QUARANTINED",
    "OUTCOME_RECOVERED",
    "RETRY_LIKE_ACTIONS",
    "TERMINAL_ACTIONS",
    "ActionExecutionError",
    "BudgetExhaustedError",
    "Checkpoint",
    "CheckpointError",
    "ClassificationError",
    "FailureClassification",
    "IntegrityFailureError",
    "PolicyDeniedError",
    "RecoveryAction",
    "RecoveryAttemptRecord",
    "RecoveryDecision",
    "RecoveryError",
    "RecoveryManager",
    "RecoveryReport",
    "RecoveryRequest",
    "ScopeViolationError",
    "build_report",
    "capture",
    "classify",
    "classify_or_unknown",
    "decide",
    "describe",
    "policy_table",
    "restore",
]
