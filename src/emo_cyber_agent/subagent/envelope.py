"""Delegation envelope contracts — POST-T018.

A TaskEnvelope is a delegation *request* carrier: WHAT is delegated, within
which scope/assets/outputs, with which requested capabilities, budget,
deadline and cancellation metadata. It grants nothing. Authorization lives
only in DelegationContext.authorization_ref, which is server-issued and can
never be derived from model/host text.
"""

from __future__ import annotations

import json
import re
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError, scan_secret_markers

SUBAGENT_CONTRACT_VERSION = "1.0.0"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_AUTHZ_RE = re.compile(r"^authz-[a-z0-9][a-z0-9\-]{2,78}$")
TRUSTED_ISSUERS: tuple[str, ...] = ("core-policy", "core-delegator")

# Collection bounds (L4): attacker-scalable scan-path inputs on the direct-API
# path. Overflow is rejected at parse (invalid). MCP path is capped separately.
MAX_ENVELOPE_ITEMS: int = 256
MAX_ENVELOPE_TOKEN_CHARS: int = 512


def _check_bounded_tokens(values: tuple[str, ...], *, field: str) -> tuple[str, ...]:
    if len(values) > MAX_ENVELOPE_ITEMS:
        raise ValueError(f"invalid: {field} exceeds {MAX_ENVELOPE_ITEMS} items ({len(values)})")
    for v in values:
        if not isinstance(v, str):
            raise ValueError(f"invalid: {field} entries must be str")
        if len(v) > MAX_ENVELOPE_TOKEN_CHARS:
            raise ValueError(f"invalid: {field} entry exceeds {MAX_ENVELOPE_TOKEN_CHARS} chars")
    return values


class DelegatedScope(BaseModel):
    """Scope shape cloned from tasks/spec.py TaskScope (narrowing-only)."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    included: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()
    target_types: tuple[str, ...] = ()

    @field_validator("included", "excluded", "target_types")
    @classmethod
    def _bounded_tokens(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return _check_bounded_tokens(tuple(v), field="scope tokens")

    def narrowed_by(self, outer: DelegatedScope) -> bool:
        """True if self fits inside outer (narrowing only, never widening)."""
        if outer.target_types and any(t not in outer.target_types for t in self.target_types):
            return False
        if outer.included and any(i not in outer.included for i in self.included):
            return False
        # Shrinking exclusions is widening (L1): every outer exclusion must
        # still be excluded inside.
        if any(e not in self.excluded for e in outer.excluded):
            return False
        return True

    def assert_narrowed_by(self, outer: DelegatedScope) -> None:
        if not self.narrowed_by(outer):
            raise HostIntegrationError(
                HostErrorCode.SCOPE_WIDENING,
                "delegated scope exceeds authorizing scope",
            )


class Budget(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    max_steps: int = Field(default=10, ge=0)
    max_tool_calls: int = Field(default=50, ge=0)
    max_seconds: int = Field(default=600, ge=0)


class CancellationMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    cancelled: bool = False
    requested_by: str = ""
    reason: str = ""
    requested_at: int = Field(default=0, ge=0)


class TaskEnvelope(BaseModel):
    """Frozen delegation request. Audit/project/snapshot-bound."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str = Field(...)
    host_id: str = Field(...)
    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    requested_task: str = Field(min_length=1, max_length=80)
    scope: DelegatedScope = Field(default_factory=DelegatedScope)
    assets: tuple[str, ...] = ()
    requested_output: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = Field(default=(), description="requested only, never granted")
    budget: Budget = Field(default_factory=Budget)
    deadline: int = Field(default=0, ge=0)
    cancellation: CancellationMetadata = Field(default_factory=CancellationMetadata)

    @field_validator("task_id", "host_id")
    @classmethod
    def _kebab(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("id must be kebab-case")
        return v

    @field_validator("assets", "requested_output", "capabilities")
    @classmethod
    def _bounded_collections(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return _check_bounded_tokens(tuple(v), field="envelope collection")

    def assert_binding(self, *, audit_id: str, project_id: str, snapshot_id: str) -> None:
        if self.audit_id != audit_id:
            raise HostIntegrationError(HostErrorCode.CROSS_AUDIT, "envelope audit binding mismatch")
        if self.project_id != project_id or self.snapshot_id != snapshot_id:
            raise HostIntegrationError(HostErrorCode.BINDING_MISMATCH, "envelope project/snapshot binding mismatch")

    def assert_scope_within(self, outer: DelegatedScope) -> None:
        self.scope.assert_narrowed_by(outer)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class DelegationContext(BaseModel):
    """Separates request from authorization.

    The request (envelope) may originate anywhere; authorization originates
    only from a trusted issuer and is referenced by ``authorization_ref``.
    ``issuer`` is allow-listed and ``authorization_ref`` must be a
    server-issued token — host/model text can never mint one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    issuer: str = Field(min_length=1, max_length=80)
    subject: str = Field(min_length=1, max_length=80)
    audience: str = Field(min_length=1, max_length=80)
    valid_from: int = Field(ge=0)
    valid_until: int = Field(ge=0)
    scope_ref: str = Field(min_length=1, max_length=120)
    authorization_ref: str = Field(min_length=1, max_length=120)

    @field_validator("issuer")
    @classmethod
    def _trusted_issuer(cls, v: str) -> str:
        if v not in TRUSTED_ISSUERS:
            raise ValueError(f"issuer is not a trusted authorization source: {v!r}")
        return v

    @field_validator("authorization_ref")
    @classmethod
    def _server_issued_ref(cls, v: str) -> str:
        if not _AUTHZ_RE.match(v):
            raise ValueError("authorization_ref must be a server-issued authz- token")
        return v

    @field_validator("valid_until")
    @classmethod
    def _window(cls, v: int) -> int:
        return v

    def is_valid_at(self, now: int) -> bool:
        return self.valid_from <= now <= self.valid_until

    @classmethod
    def issue(
        cls,
        *,
        issuer: str,
        subject: str,
        audience: str,
        valid_from: int,
        valid_until: int,
        scope_ref: str,
        authorization_ref: str,
        server: bool = False,
    ) -> Self:
        """Server-only issuance path. ``server=True`` may only be passed by Core."""
        if not server:
            raise HostIntegrationError(
                HostErrorCode.AUTHZ_FORGED,
                "delegation authorization must be issued server-side",
            )
        if valid_until <= valid_from:
            raise HostIntegrationError(HostErrorCode.INVALID, "validity window is empty or inverted")
        return cls(
            issuer=issuer,
            subject=subject,
            audience=audience,
            valid_from=valid_from,
            valid_until=valid_until,
            scope_ref=scope_ref,
            authorization_ref=authorization_ref,
        )

    @classmethod
    def from_host_text(cls, host_text: str, **kwargs: Any) -> Self:
        """Host/model text can never mint authorization. Always raises."""
        raise HostIntegrationError(
            HostErrorCode.AUTHZ_FORGED,
            "authorization cannot be minted from host/model text",
            reason=(host_text[:80] if host_text else "empty"),
        )

    def assert_authorized_for(self, envelope: TaskEnvelope, *, now: int) -> None:
        if self.audience != envelope.host_id:
            raise HostIntegrationError(HostErrorCode.AUTHZ_FORGED, "delegation audience does not match host")
        if not self.is_valid_at(now):
            raise HostIntegrationError(HostErrorCode.EXPIRED, "delegation validity window does not cover now")
        if not self.scope_ref:
            raise HostIntegrationError(HostErrorCode.INVALID, "delegation has no scope binding")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def assert_authorization_independent(authorization_ref: str, *untrusted_texts: str) -> None:
    """Fail if a server-issued ref appears inside untrusted text (leak/mint)."""
    for text in untrusted_texts:
        if authorization_ref and authorization_ref in (text or ""):
            raise HostIntegrationError(
                HostErrorCode.AUTHZ_FORGED,
                "authorization_ref observed inside untrusted text",
            )
    if scan_secret_markers(authorization_ref):
        raise HostIntegrationError(HostErrorCode.INVALID, "authorization_ref carries secret markers")
