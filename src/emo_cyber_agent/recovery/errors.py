"""Typed errors for the bounded recovery layer.

Recovery must FAIL CLOSED: every failure surfaces as a typed error from this
module rather than an ad-hoc exception. Callers catch these to populate the
recovery report (DATA, never instructions).
"""

from __future__ import annotations


class RecoveryError(Exception):
    """Base class for all recovery-layer errors."""


class ClassificationError(RecoveryError):
    """Raised when a failure cannot be classified into a known category."""


class PolicyDeniedError(RecoveryError):
    """Raised when recovery is refused by policy. Never retried."""

    def __init__(self, message: str = "Recovery denied by policy", *, reason: str = "") -> None:
        detail = f"{message}: {reason}" if reason else message
        super().__init__(detail)
        self.reason = reason


class IntegrityFailureError(RecoveryError):
    """Raised on integrity violations. Always fail-closed, never retried."""

    def __init__(self, message: str = "Integrity failure", *, reason: str = "") -> None:
        detail = f"{message}: {reason}" if reason else message
        super().__init__(detail)
        self.reason = reason


class CheckpointError(RecoveryError):
    """Raised on checkpoint capture/restore failures (corrupt, missing, foreign)."""


class ScopeViolationError(RecoveryError):
    """Raised when a recovery operation would expand scope or cross audits."""


class BudgetExhaustedError(RecoveryError):
    """Raised when the bounded-retry budget is exhausted. Fail closed."""


class ActionExecutionError(RecoveryError):
    """Raised when a bounded recovery action itself fails."""
