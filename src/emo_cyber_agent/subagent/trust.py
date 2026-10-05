"""Typed host-integration errors — POST-T018.

Fail-closed boundary style cloned from ``recovery/errors.py``: every
host/subagent failure surfaces as a typed error carrying a machine-readable
code. ``quarantine=True`` tells the caller the session must be quarantined
rather than retried.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

_TRUST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")

_SECRET_MARKERS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "authorization:",
    "aws_secret",
    "bearer ",
    "client_secret",
    "password",
    "private_key",
    "secret",
    "token",
)


def scan_secret_markers(text: str) -> list[str]:
    """Return secret-marker hits (case-insensitive). Pure scan, never a verdict."""
    lowered = (text or "").lower()
    return [m for m in _SECRET_MARKERS if m in lowered]


class ContextClassification(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    SANITIZED = "sanitized"


class SecurityDecision(StrEnum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    DENY = "deny"


class HostErrorCode(StrEnum):
    BINDING_MISMATCH = "SUBAGENT_BINDING_MISMATCH"
    CROSS_AUDIT = "SUBAGENT_CROSS_AUDIT"
    AUTHZ_FORGED = "SUBAGENT_AUTHZ_FORGED"
    SESSION_MISMATCH = "SUBAGENT_SESSION_MISMATCH"
    COMPAT_UNKNOWN = "SUBAGENT_COMPAT_UNKNOWN"
    COMPAT_INCOMPATIBLE = "SUBAGENT_COMPAT_INCOMPATIBLE"
    CAPABILITY_WIDENING = "SUBAGENT_CAPABILITY_WIDENING"
    CAPABILITY_DENIED = "SUBAGENT_CAPABILITY_DENIED"
    SCOPE_WIDENING = "SUBAGENT_SCOPE_WIDENING"
    EXPIRED = "SUBAGENT_EXPIRED"
    INVALID = "SUBAGENT_INVALID"


class HostIntegrationError(Exception):
    """Base class for all subagent host-integration errors."""

    def __init__(self, code: HostErrorCode, message: str, *, reason: str = "", quarantine: bool = False) -> None:
        detail = f"{code.value}: {message}"
        if reason:
            detail = f"{detail}: {reason}"
        super().__init__(detail)
        self.code = code
        self.reason = reason
        self.quarantine = quarantine


class ContextTrust(BaseModel):
    """Trust metadata for inbound context. UNTRUSTED default; scope-bound."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(...)
    classification: ContextClassification = ContextClassification.UNTRUSTED
    scope_ref: str = Field(min_length=1, max_length=120)
    sanitized: bool = False

    @field_validator("source")
    @classmethod
    def _source(cls, v: str) -> str:
        if not _TRUST_ID_RE.match(v):
            raise ValueError("source must be kebab-case")
        return v

    def assert_scope(self, expected_scope_ref: str) -> None:
        if self.scope_ref != expected_scope_ref:
            raise HostIntegrationError(
                HostErrorCode.BINDING_MISMATCH,
                "context scope binding mismatch",
                quarantine=True,
            )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class DelegationSecurityDecision(BaseModel):
    """Outcome of trust evaluation. Records reasons; permits nothing itself."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: SecurityDecision
    reasons: tuple[str, ...] = ()
    evaluated_at: int = Field(ge=0)

    def requires_quarantine(self) -> bool:
        return self.decision in (SecurityDecision.QUARANTINE, SecurityDecision.DENY)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def evaluate_context_trust(context: ContextTrust, *, untrusted_text: str = "", evaluated_at: int = 0) -> DelegationSecurityDecision:
    """Deterministic trust evaluation helper.

    UNTRUSTED (the default) never maps to ALLOW without sanitization;
    secret markers force QUARANTINE. Pure helper — callers (Core) decide.
    """
    hits = scan_secret_markers(untrusted_text)
    if hits:
        return DelegationSecurityDecision(
            decision=SecurityDecision.QUARANTINE,
            reasons=(f"secret markers observed: {','.join(sorted(hits))}",),
            evaluated_at=evaluated_at,
        )
    if context.classification == ContextClassification.UNTRUSTED and not context.sanitized:
        return DelegationSecurityDecision(
            decision=SecurityDecision.SANITIZE,
            reasons=("context is untrusted and unsanitized",),
            evaluated_at=evaluated_at,
        )
    if context.classification == ContextClassification.SANITIZED or context.sanitized:
        return DelegationSecurityDecision(
            decision=SecurityDecision.ALLOW,
            reasons=("context sanitized",),
            evaluated_at=evaluated_at,
        )
    return DelegationSecurityDecision(
        decision=SecurityDecision.ALLOW,
        reasons=("context trusted",),
        evaluated_at=evaluated_at,
    )
