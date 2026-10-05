"""Change analysis contracts — POST-RC-008.

Facts about change, not verdicts. Every model is frozen,
extra-forbidden, audit/project/snapshot bound, with deterministic
serialization. No severity, no confirmation, no lifecycle states
borrowed from Findings.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

CHANGE_CONTRACT_VERSION = "1.0"

# Closed file-change states. UNKNOWN means "could not compare" and
# must never be treated as UNCHANGED.
FILE_CHANGE_STATES: tuple[str, ...] = ("ADDED", "REMOVED", "MODIFIED", "RENAMED", "MOVED", "UNCHANGED", "UNKNOWN")

# Closed change classification taxonomy. Deterministic from facts only.
CHANGE_CLASSIFICATIONS: tuple[str, ...] = (
    "CODE_BEHAVIOR", "AUTHORIZATION", "AUTHENTICATION", "INPUT_HANDLING",
    "OUTPUT_HANDLING", "CRYPTO", "SECRET_HANDLING", "DEPENDENCY",
    "CONFIGURATION", "NETWORK", "FILE_ACCESS", "DATABASE", "ROUTING",
    "STATE_CHANGE", "INFRASTRUCTURE", "UNKNOWN",
)

# Closed security predicate signals. Signals, never findings.
CHANGE_PREDICATES: tuple[str, ...] = (
    "AUTH_BOUNDARY_CHANGED", "STATE_CHANGE_ADDED", "NEW_EXTERNAL_INPUT",
    "NEW_SINK", "NEW_TAINT_PATH", "TAINT_PATH_MODIFIED",
    "ROUTE_PERMISSION_CHANGED", "DEPENDENCY_VERSION_CHANGED",
    "SECRET_HANDLING_CHANGED", "FILE_ACCESS_CHANGED",
    "DATABASE_ACCESS_CHANGED", "CONFIG_SECURITY_CHANGE",
)

# Review modes with explicit coverage semantics.
REVIEW_MODES: tuple[str, ...] = ("FULL_REVIEW", "TARGETED_REVIEW", "REBASE_REVIEW")

# Baseline observation comparison outcomes. REMOVED means "absent from
# the target snapshot under the comparison contract" — it is NOT the
# Finding lifecycle state RESOLVED.
BASELINE_STATES: tuple[str, ...] = ("NEW", "PERSISTING", "REMOVED", "CHANGED", "UNRESOLVED", "INDETERMINATE")

# Verdict vocabulary banned from every change-analysis output value.
VERDICT_TOKENS: tuple[str, ...] = ("vulnerable", "safe", "confirmed", "critical", "fixed")


def canonical_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


def assert_no_verdicts(*texts: str) -> None:
    from emo_cyber_agent.change_analysis.errors import ChangeError, ChangeErrorCode

    for text in texts:
        lowered = (text or "").lower()
        for token in VERDICT_TOKENS:
            if token in lowered:
                raise ChangeError(ChangeErrorCode.INVALID, f"verdict vocabulary denied in change layer: {token}")


class ComparisonSnapshot(BaseModel):
    """Normalized snapshot input. Built by the caller from Repository +
    Code Intelligence contracts; this layer never shells git."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(default="", max_length=200)
    revision: str = Field(default="", max_length=120)
    files: dict[str, str] = Field(default_factory=dict)
    source_provenance: str = Field(default="", max_length=300)


class ChangedRegion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: str = Field(..., min_length=1, max_length=512)
    start_line: int = Field(default=1, ge=1)
    end_line: int = Field(default=1, ge=1)
    kind: str = Field(default="MODIFIED", max_length=24)


class ChangedFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: str = Field(..., min_length=1, max_length=512)
    previous_path: str = Field(default="", max_length=512)
    state: str = Field(...)
    generated: bool = False
    regions: tuple[ChangedRegion, ...] = ()
    classifications: tuple[str, ...] = ()

    @field_validator("state")
    @classmethod
    def _state(cls, v: str) -> str:
        if v not in FILE_CHANGE_STATES:
            raise ValueError(f"unknown file change state: {v}")
        return v


class ChangedSymbol(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    symbol_id: str = Field(..., min_length=1, max_length=320)
    path: str = Field(..., min_length=1, max_length=512)
    change: str = Field(default="MODIFIED", max_length=24)
    classifications: tuple[str, ...] = ()


class ChangedRoute(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    endpoint_id: str = Field(..., min_length=1, max_length=320)
    change: str = Field(default="MODIFIED", max_length=24)
    auth_boundary_changed: bool = False


class ChangedDependency(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    package: str = Field(..., min_length=1, max_length=200)
    previous_version: str = Field(default="", max_length=40)
    current_version: str = Field(default="", max_length=40)
    manifest_path: str = Field(default="", max_length=512)


class ChangedDatabaseRelation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    relation_id: str = Field(..., min_length=1, max_length=320)
    change: str = Field(default="MODIFIED", max_length=24)
    database_object: str = Field(default="", max_length=320)


class ChangeClassification(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    subject: str = Field(..., min_length=1, max_length=320)
    subject_kind: str = Field(default="file", max_length=40)
    classifications: tuple[str, ...] = ()
    reason: str = Field(default="", max_length=500)


class ChangeSet(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(default="", max_length=200)
    base_snapshot_id: str = Field(..., min_length=1, max_length=160)
    target_snapshot_id: str = Field(..., min_length=1, max_length=160)
    base_revision: str = Field(default="", max_length=120)
    target_revision: str = Field(default="", max_length=120)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_provenance: str = Field(default="", max_length=300)
    files: tuple[ChangedFile, ...] = ()
    symbols: tuple[ChangedSymbol, ...] = ()
    routes: tuple[ChangedRoute, ...] = ()
    dependencies: tuple[ChangedDependency, ...] = ()
    database_relations: tuple[ChangedDatabaseRelation, ...] = ()
    classifications: tuple[ChangeClassification, ...] = ()
    coverage: str = Field(default="complete", max_length=24)
    limitations: tuple[str, ...] = ()
    change_digest: str = Field(default="", max_length=128)


class AffectedSurface(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    symbols: tuple[str, ...] = ()
    routes: tuple[str, ...] = ()
    boundaries: tuple[str, ...] = ()
    dataflow_nodes: tuple[str, ...] = ()
    database_objects: tuple[str, ...] = ()
    components: tuple[str, ...] = ()


class SecurityImpact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    affected: bool = False
    domains: tuple[str, ...] = ()
    affected_assets: tuple[str, ...] = ()
    affected_routes: tuple[str, ...] = ()
    affected_symbols: tuple[str, ...] = ()
    affected_tools: tuple[str, ...] = ()
    affected_skills: tuple[str, ...] = ()
    surface: AffectedSurface = Field(default_factory=AffectedSurface)
    evidence_ids: tuple[str, ...] = ()
    confidence_context: str = Field(default="structural-facts-only", max_length=80)
    coverage: str = Field(default="complete", max_length=24)
    limitations: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()


class VerificationHandoff(BaseModel):
    """A change worth verifying. Handoff only: never executes, never
    reuses stale results without a compatibility check."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    handoff_id: str = Field(..., min_length=1, max_length=160)
    target_snapshot_id: str = Field(..., min_length=1, max_length=160)
    method: str = Field(..., min_length=1, max_length=60)
    target: str = Field(..., min_length=1, max_length=320)
    reason: str = Field(default="", max_length=500)
    compatible_snapshots: tuple[str, ...] = ()


class ChangeReviewPlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    plan_id: str = Field(..., min_length=1, max_length=160)
    audit_id: str = Field(..., min_length=1, max_length=120)
    review_mode: str = Field(...)
    targeted_skills: tuple[str, ...] = ()
    targeted_packs: tuple[str, ...] = ()
    targeted_tasks: tuple[str, ...] = ()
    required_codeintel_capabilities: tuple[str, ...] = ()
    required_tools: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    verification_handoffs: tuple[VerificationHandoff, ...] = ()
    coverage_statement: str = Field(default="", max_length=1000)
    limitations: tuple[str, ...] = ()
    plan_digest: str = Field(default="", max_length=128)

    @field_validator("review_mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        if v not in REVIEW_MODES:
            raise ValueError(f"unknown review mode: {v}")
        return v


class BaselineSecurityObservation(BaseModel):
    """Before-vs-after comparison of observations/evidence only. The
    REMOVED state describes snapshot presence, never Finding status."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    observation_key: str = Field(..., min_length=1, max_length=320)
    state: str = Field(...)
    before_digest: str = Field(default="", max_length=128)
    after_digest: str = Field(default="", max_length=128)
    evidence_ids: tuple[str, ...] = ()

    @field_validator("state")
    @classmethod
    def _state(cls, v: str) -> str:
        if v not in BASELINE_STATES:
            raise ValueError(f"unknown baseline state: {v}")
        if v == "RESOLVED":
            raise ValueError("RESOLVED is a Finding lifecycle state, denied here")
        return v


class ChangeReportView(BaseModel):
    """Projection-only metadata for reports. No findings, no verdicts."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    base_revision: str = ""
    target_revision: str = ""
    changed_files: tuple[str, ...] = ()
    affected_domains: tuple[str, ...] = ()
    review_mode: str = ""
    coverage: str = ""
    limitations: tuple[str, ...] = ()
    targeted_checks: tuple[str, ...] = ()
    evidence_references: tuple[str, ...] = ()
    verification_handoffs: tuple[str, ...] = ()
