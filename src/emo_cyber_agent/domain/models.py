"""Domain models for audits, evidence and findings.

These models are the single source of truth for audit data.
They align with the JSON schemas in docs/schemas/ and are validated
with Pydantic v2.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AuditStatus(StrEnum):
    CREATED = "created"
    PLANNING = "planning"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    VERIFYING = "verifying"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    SUSPECTED = "suspected"
    SUPPORTED = "supported"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    ACCEPTED_RISK = "accepted_risk"
    NOT_REPRODUCIBLE = "not_reproducible"


class VerificationStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"
    REFUTED = "refuted"
    UNRESOLVED = "unresolved"


class ToolInvocationStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_data(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Asset(BaseModel):
    """A security-relevant object in the target."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = Field(..., description="Asset kind: file, repo, endpoint, etc.")
    locator: str = Field(..., description="Path, URL, or reference to the asset")
    line_start: int | None = Field(None, ge=1)
    line_end: int | None = Field(None, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("locator")
    @classmethod
    def locator_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("locator must be non-empty")
        return v


class EvidenceItem(BaseModel):
    """A normalized observation with full provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_tool: str = Field(..., min_length=1, description="Tool or provider name")
    source_version: str | None = Field(None, description="Version of the source tool")
    target_asset_id: str | None = Field(None, description="ID of the related Asset")
    timestamp: str = Field(default_factory=_now_iso)
    location: str | None = Field(None, description="File path, line, or URL")
    content_hash: str | None = Field(None, description="SHA-256 of the evidence content")
    content_summary: str = Field(..., min_length=1, description="Sanitized summary; no raw secrets")
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("content_summary")
    @classmethod
    def summary_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("content_summary must be non-empty")
        return v


class Verification(BaseModel):
    """Record of an attempt to verify a finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = Field(..., min_length=1)
    status: VerificationStatus = VerificationStatus.PENDING
    method: str = Field(..., min_length=1)
    environment: str = Field(default="local", min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=_now_iso)
    residual_uncertainty: str = Field(default="", min_length=0)


class ToolInvocation(BaseModel):
    """Immutable record of a tool execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str = Field(..., min_length=1)
    tool_version: str | None = Field(None)
    status: ToolInvocationStatus = ToolInvocationStatus.SUCCESS
    duration_ms: float = Field(default=0.0, ge=0)
    input_hash: str | None = Field(None, description="SHA-256 of normalized input")
    output_summary: str = Field(default="", description="Sanitized output; no secrets")
    error_summary: str | None = Field(None)
    timestamp: str = Field(default_factory=_now_iso)
    safe_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool_name")
    @classmethod
    def name_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("tool_name must be non-empty")
        return v


class Finding(BaseModel):
    """A normalized security finding derived from evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = Field(..., min_length=1)
    severity: FindingSeverity
    confidence: float = Field(..., ge=0.0, le=1.0)
    status: FindingStatus = FindingStatus.SUSPECTED
    asset_id: str | None = Field(None)
    taxonomy: dict[str, Any] = Field(
        default_factory=lambda: {"cwe": None, "owasp": None, "cvss": None}
    )
    description: str = Field(..., min_length=1)
    impact: str = Field(..., min_length=1)
    preconditions: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    verification: Verification | None = Field(None)
    remediation: str = Field(..., min_length=1)
    references: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def confidence_valid(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("findings require at least one evidence item")
        return v


class AuditJob(BaseModel):
    """Represents one audit execution and its lifecycle."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str = Field(..., min_length=1)
    mode: str = Field(default="standard")
    permission_profile: str = Field(default="read_only")
    status: AuditStatus = AuditStatus.CREATED
    created_at: str = Field(default_factory=_now_iso)
    completed_at: str | None = None
    asset_ids: list[str] = Field(default_factory=list)
    tool_invocation_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def target_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target must be non-empty")
        return v

    def transition_to(self, new_status: AuditStatus) -> AuditJob:
        """Return a new AuditJob with the updated status."""
        valid_transitions: dict[AuditStatus, list[AuditStatus]] = {
            AuditStatus.CREATED: [AuditStatus.PLANNING, AuditStatus.FAILED, AuditStatus.CANCELLED],
            AuditStatus.PLANNING: [AuditStatus.COLLECTING, AuditStatus.FAILED, AuditStatus.CANCELLED],
            AuditStatus.COLLECTING: [AuditStatus.ANALYZING, AuditStatus.FAILED, AuditStatus.CANCELLED],
            AuditStatus.ANALYZING: [AuditStatus.VERIFYING, AuditStatus.REPORTING, AuditStatus.FAILED, AuditStatus.CANCELLED],
            AuditStatus.VERIFYING: [AuditStatus.REPORTING, AuditStatus.FAILED, AuditStatus.CANCELLED],
            AuditStatus.REPORTING: [AuditStatus.COMPLETED, AuditStatus.FAILED, AuditStatus.CANCELLED],
            AuditStatus.COMPLETED: [],
            AuditStatus.FAILED: [],
            AuditStatus.CANCELLED: [],
        }
        allowed = valid_transitions.get(self.status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Invalid transition from {self.status.value} to {new_status.value}"
            )
        return AuditJob(
            **{
                **self.model_dump(),
                "status": new_status,
                "completed_at": _now_iso()
                if new_status in (AuditStatus.COMPLETED, AuditStatus.FAILED, AuditStatus.CANCELLED)
                else None,
            }
        )


class Coverage(BaseModel):
    """Coverage summary for an audit result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    controls_total: int = Field(default=0, ge=0)
    controls_evaluated: int = Field(default=0, ge=0)
    controls_not_evaluated: int = Field(default=0, ge=0)
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_totals(self) -> Coverage:
        expected = self.controls_evaluated + self.controls_not_evaluated
        if self.controls_total > 0 and expected != self.controls_total:
            raise ValueError(
                f"controls_evaluated + controls_not_evaluated ({expected}) "
                f"must equal controls_total ({self.controls_total})"
            )
        return self


class AuditResult(BaseModel):
    """Final consolidated audit output."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="0.1.0", pattern=r"^\d+\.\d+$")
    audit_id: str = Field(..., min_length=1)
    status: AuditStatus
    target: str = Field(..., min_length=1)
    mode: str = Field(default="standard")
    permission_profile: str = Field(default="read_only")
    coverage: Coverage = Field(default_factory=Coverage)
    findings: list[Finding] = Field(default_factory=list)
    tool_failures: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_now_iso)
    completed_at: str | None = None

    @field_validator("target")
    @classmethod
    def target_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target must be non-empty")
        return v
