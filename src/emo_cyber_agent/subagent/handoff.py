"""Result/handoff contracts — POST-T018.

AuditHandoff carries finding/evidence/verification references, report ref,
limitations, recovery state and a provenance chain back to the delegation.
ResultEnvelope wraps status + handoff + compat + health snapshot. Structured
references only: no chain-of-thought, no secrets, no raw model output.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.subagent.hosts import CompatibilityDecision, CompatibilityVerdict
from emo_cyber_agent.subagent.session import SubagentHealth, SubagentLifecycle
from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError, scan_secret_markers


class ResultStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    QUARANTINED = "quarantined"


class ProvenanceLink(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    task_id: str = Field(min_length=1, max_length=80)
    session_id: str = Field(min_length=1, max_length=80)
    authorization_ref: str = Field(min_length=1, max_length=120)
    recorded_at: int = Field(ge=0)


class AuditHandoff(BaseModel):
    """Frozen audit handoff. Audit/project/snapshot-bound; references only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    finding_refs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    verification_refs: tuple[str, ...] = ()
    report_ref: str = ""
    limitations: tuple[str, ...] = ()
    recovery_state: str = Field(default="none", max_length=64)
    provenance: tuple[ProvenanceLink, ...] = ()

    @field_validator("finding_refs", "evidence_refs", "verification_refs", "limitations")
    @classmethod
    def _clean_refs(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for item in v:
            if not item or not item.strip():
                raise ValueError("reference tokens must be non-empty strings")
            if scan_secret_markers(item):
                raise ValueError("references must not carry secret material")
        return v

    @field_validator("report_ref")
    @classmethod
    def _report_ref(cls, v: str) -> str:
        if v and scan_secret_markers(v):
            raise ValueError("report_ref must not carry secret material")
        return v

    def assert_binding(self, *, audit_id: str, project_id: str, snapshot_id: str) -> None:
        if self.audit_id != audit_id:
            raise HostIntegrationError(HostErrorCode.CROSS_AUDIT, "handoff audit binding mismatch")
        if self.project_id != project_id or self.snapshot_id != snapshot_id:
            raise HostIntegrationError(HostErrorCode.BINDING_MISMATCH, "handoff project/snapshot binding mismatch")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class HealthSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    health: SubagentHealth = SubagentHealth.READY
    state: SubagentLifecycle = SubagentLifecycle.REPORTING
    note: str = Field(default="", max_length=300)

    @field_validator("note")
    @classmethod
    def _note(cls, v: str) -> str:
        if v and scan_secret_markers(v):
            raise ValueError("health note must not carry secret material")
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class ResultEnvelope(BaseModel):
    """Structured delegation result. No CoT, no secrets, no raw output."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ResultStatus
    task_id: str = Field(min_length=1, max_length=80)
    session_id: str = Field(min_length=1, max_length=80)
    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    handoff: AuditHandoff
    compatibility: CompatibilityDecision
    health: HealthSnapshot = Field(default_factory=HealthSnapshot)
    completed_at: int = Field(ge=0)

    def assert_binding(self, *, audit_id: str, project_id: str, snapshot_id: str) -> None:
        if self.audit_id != audit_id:
            raise HostIntegrationError(HostErrorCode.CROSS_AUDIT, "result audit binding mismatch")
        if self.project_id != project_id or self.snapshot_id != snapshot_id:
            raise HostIntegrationError(HostErrorCode.BINDING_MISMATCH, "result project/snapshot binding mismatch")
        self.handoff.assert_binding(audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id)
        if self.compatibility.verdict == CompatibilityVerdict.UNKNOWN:
            raise HostIntegrationError(
                HostErrorCode.COMPAT_UNKNOWN,
                "result carries unknown compatibility — quarantining",
                quarantine=True,
            )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
