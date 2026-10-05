"""Capability envelope contracts — POST-T018.

Capabilities are *requested* by the envelope and *computed* server-side into
an EffectiveCapabilitySet. Narrowing-only: effective ⊆ requested, effective
⊆ allowed, effective ∩ denied = ∅. Inherited context never widens the grant.
"""

from __future__ import annotations

import json
import re
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
SERVER_COMPUTED_BY = "core-policy"


class CapabilityEnvelope(BaseModel):
    """Requested/allowed/denied/inherited capability lists. Audit-bound."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    requested: tuple[str, ...] = ()
    allowed: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    inherited: tuple[str, ...] = ()

    @field_validator("requested", "allowed", "denied", "inherited")
    @classmethod
    def _tokens(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for item in v:
            if not item or not item.strip():
                raise ValueError("capability tokens must be non-empty strings")
        return v

    def assert_binding(self, *, audit_id: str, project_id: str, snapshot_id: str) -> None:
        if self.audit_id != audit_id:
            raise HostIntegrationError(HostErrorCode.CROSS_AUDIT, "capability audit binding mismatch")
        if self.project_id != project_id or self.snapshot_id != snapshot_id:
            raise HostIntegrationError(HostErrorCode.BINDING_MISMATCH, "capability project/snapshot binding mismatch")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class EffectiveCapabilitySet(BaseModel):
    """Server-computed effective grant. Frozen; narrowing-only enforced."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    effective: tuple[str, ...] = ()
    requested_snapshot: tuple[str, ...] = ()
    denied_snapshot: tuple[str, ...] = ()
    policy_version: str = Field(min_length=5, max_length=32)
    computed_by: str = Field(min_length=1, max_length=80)
    computed_at: int = Field(ge=0)

    @field_validator("policy_version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not _SEMVER_RE.match(v):
            raise ValueError("policy_version must be semver X.Y.Z")
        return v

    @model_validator(mode="after")
    def _narrowing_only(self) -> Self:
        if self.computed_by != SERVER_COMPUTED_BY:
            raise ValueError(f"effective set must be computed server-side by {SERVER_COMPUTED_BY}")
        requested = set(self.requested_snapshot)
        if not set(self.effective) <= requested:
            raise ValueError("effective capabilities must be a subset of requested (narrowing-only)")
        if set(self.effective) & set(self.denied_snapshot):
            raise ValueError("effective capabilities must not intersect denied")
        return self

    @classmethod
    def compute(
        cls,
        envelope: CapabilityEnvelope,
        *,
        policy_version: str,
        computed_at: int,
        server: bool = False,
        computed_by: str = SERVER_COMPUTED_BY,
    ) -> Self:
        """Server-only computation. ``server=True`` may only be passed by Core Policy."""
        if not server or computed_by != SERVER_COMPUTED_BY:
            raise HostIntegrationError(
                HostErrorCode.CAPABILITY_DENIED,
                "effective capabilities must be computed server-side",
            )
        narrowed = sorted((set(envelope.requested) & set(envelope.allowed)) - set(envelope.denied))
        return cls(
            audit_id=envelope.audit_id,
            project_id=envelope.project_id,
            snapshot_id=envelope.snapshot_id,
            effective=tuple(narrowed),
            requested_snapshot=envelope.requested,
            denied_snapshot=envelope.denied,
            policy_version=policy_version,
            computed_by=computed_by,
            computed_at=computed_at,
        )

    def allows(self, capability: str) -> bool:
        return capability in set(self.effective)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
