"""Failure classification taxonomy for bounded recovery.

Classification answers ONE question: what kind of failure is this? It performs
no recovery itself and grants no capability. Unknown or hostile input maps to
UNKNOWN, which the policy resolves to FAIL_CLOSED.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class FailureClassification(str, Enum):
    """Exhaustive failure taxonomy. Ten categories, no more."""

    TRANSIENT = "TRANSIENT"
    STALE_CONTEXT = "STALE_CONTEXT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    DEPENDENCY_MISMATCH = "DEPENDENCY_MISMATCH"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    POLICY_DENIED = "POLICY_DENIED"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    UNKNOWN = "UNKNOWN"


def _normalize_token(value: Any) -> str:
    if isinstance(value, FailureClassification):
        return value.value
    if isinstance(value, str):
        return value.strip().upper().replace("-", "_").replace(" ", "_")
    raise ValueError(f"Cannot classify value of type {type(value).__name__}: {value!r}")


def classify(value: Any) -> FailureClassification:
    """Parse *value* into a FailureClassification.

    Raises:
        ClassificationError: if the value is not a known category.
    """
    from .errors import ClassificationError

    try:
        token = _normalize_token(value)
    except ValueError as exc:
        raise ClassificationError(str(exc)) from exc
    try:
        return FailureClassification[token]
    except KeyError:
        # Accept exact wire values too (same set, but be explicit).
        try:
            return FailureClassification(str(token))
        except ValueError as exc:
            raise ClassificationError(f"Unknown failure classification: {value!r}") from exc


def classify_or_unknown(value: Any) -> FailureClassification:
    """Lenient variant: unrecognized input maps to UNKNOWN (fail-closed downstream)."""
    from .errors import ClassificationError

    try:
        return classify(value)
    except ClassificationError:
        return FailureClassification.UNKNOWN
