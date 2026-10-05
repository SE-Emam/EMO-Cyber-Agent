"""Threat modeling domain — POST-RC-009.

Security representations, hypotheses, scenarios, controls, and
coverage facts. Frozen, typed, extra-forbidden, audit/project/
snapshot-bound, deterministic digests. No severity, no
confirmation, no exploitability, no remediation execution.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

THREAT_MODEL_CONTRACT_VERSION = "1.0"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_VER_RE = re.compile(r"^\d+\.\d+\.\d+$")

BOUNDARY_KINDS: tuple[str, ...] = (
    "TRUST", "AUTHORIZATION", "AUTHENTICATION", "NETWORK",
    "DATA_SENSITIVITY", "PRIVILEGE",
)
BOUNDARY_BASIS: tuple[str, ...] = ("OBSERVED", "INFERRED", "DECLARED", "UNKNOWN")

SURFACE_CATEGORIES: tuple[str, ...] = (
    "INBOUND", "OUTBOUND", "DATA_ACCESS", "STATE_CHANGE",
    "AUTHENTICATION", "AUTHORIZATION", "FILE_ACCESS",
    "DATABASE_ACCESS", "NETWORK_ACCESS", "SECRET_ACCESS",
    "ADMINISTRATIVE",
)

COVERAGE_STATES: tuple[str, ...] = (
    "NONE_OBSERVED", "FULLY_MAPPED", "PARTIALLY_MAPPED",
    "NOT_ANALYZED", "UNKNOWN",
)

STRIDE_CATEGORIES: tuple[str, ...] = (
    "SPOOFING", "TAMPERING", "REPUDIATION", "INFORMATION_DISCLOSURE",
    "DENIAL_OF_SERVICE", "ELEVATION_OF_PRIVILEGE",
)

HYPOTHESIS_STATUS: tuple[str, ...] = (
    "UNASSESSED", "HYPOTHESIZED", "SUPPORTED_BY_EVIDENCE",
    "REFUTED", "INCONCLUSIVE",
)

PATH_CLASSES: tuple[str, ...] = ("POSSIBLE_PATH", "SUPPORTED_PATH", "VERIFIED_PATH")

CONTROL_KINDS: tuple[str, ...] = (
    "AUTHENTICATION", "AUTHORIZATION", "VALIDATION", "ENCODING",
    "RATE_LIMITING", "AUDITING", "ENCRYPTION", "SECRETS_MANAGEMENT",
    "NETWORK_ISOLATION", "INPUT_SANITIZATION", "OUTPUT_ENCODING",
)

CONTROL_STATUS: tuple[str, ...] = (
    "OBSERVED_CONTROL", "EXPECTED_CONTROL", "UNVERIFIED_CONTROL",
)

DELTA_KINDS: tuple[str, ...] = (
    "NEW_THREAT_SCENARIO", "REMOVED_SCENARIO", "CHANGED_SCENARIO",
    "PERSISTING_SCENARIO", "NEW_ATTACK_SURFACE", "REMOVED_ATTACK_SURFACE",
    "CHANGED_BOUNDARY", "CHANGED_CONTROL", "COVERAGE_CHANGE",
    "UNKNOWN_CHANGE",
)

# Vocabulary this layer must never emit as its own authority.
THREAT_VERDICT_TOKENS: tuple[str, ...] = (
    "confirmed_vulnerability", "confirm_vulnerability", "confirm vulnerability",
    "critical", "exploitable", "exploit_confirmed", "exploit confirmed",
    "fixed", "severity",
)


class PackTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"


def canonical_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


def stable_id(prefix: str, *parts: str, limit: int = 78) -> str:
    """Deterministic kebab-case id that always fits the length rule."""
    import re as _re

    slug = _re.sub(r"[^a-z0-9]+", "-", "-".join([prefix, *[str(p or "") for p in parts]]).lower()).strip("-")
    if len(slug) <= limit:
        return slug or "unnamed"
    digest = canonical_digest({"id": slug})[:12]
    head = slug[: max(8, limit - 13)].strip("-") or "item"
    return f"{head}-{digest}"


def assert_no_threat_verdicts(*texts: str) -> None:
    from emo_cyber_agent.threat_modeling.errors import ThreatModelError, ThreatModelErrorCode

    for text in texts:
        lowered = (text or "").lower()
        for token in THREAT_VERDICT_TOKENS:
            if token in lowered:
                raise ThreatModelError(ThreatModelErrorCode.INVALID, f"threat verdict vocabulary denied: {token}")


class SystemActor(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    actor_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=160)
    kind: str = Field(default="external-user", max_length=60)

    @field_validator("actor_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("actor_id must be kebab-case")
        return v


class SystemComponent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    component_id: str = Field(...)
    kind: str = Field(..., min_length=1, max_length=60)
    name: str = Field(..., min_length=1, max_length=200)
    symbols: tuple[str, ...] = ()

    @field_validator("component_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("component_id must be kebab-case")
        return v


class SystemAsset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    asset_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=200)
    kind: str = Field(default="data", max_length=60)
    provenance_kind: str = Field(default="UNKNOWN", max_length=24)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("asset_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("asset_id must be kebab-case")
        return v

    @field_validator("provenance_kind")
    @classmethod
    def _provenance_kind(cls, v: str) -> str:
        if v not in ("OBSERVED", "DECLARED", "INFERRED", "UNKNOWN"):
            raise ValueError(f"asset provenance kind not allowed: {v}")
        return v


class SystemDataStore(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    store_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=200)
    kind: str = Field(default="database", max_length=60)

    @field_validator("store_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("store_id must be kebab-case")
        return v


class SystemProcess(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    process_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=200)
    symbols: tuple[str, ...] = ()

    @field_validator("process_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("process_id must be kebab-case")
        return v


class SystemDataFlow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    flow_id: str = Field(...)
    source: str = Field(..., min_length=1, max_length=320)
    target: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(default="data", max_length=60)
    crosses: tuple[str, ...] = ()

    @field_validator("flow_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("flow_id must be kebab-case")
        return v


class TrustBoundary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    boundary_id: str = Field(...)
    kind: str = Field(...)
    basis: str = Field(default="UNKNOWN", max_length=24)
    provenance: dict[str, Any] = Field(default_factory=dict)
    protects: tuple[str, ...] = ()

    @field_validator("boundary_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("boundary_id must be kebab-case")
        return v

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in BOUNDARY_KINDS:
            raise ValueError(f"boundary kind not allowed: {v}")
        return v

    @field_validator("basis")
    @classmethod
    def _basis(cls, v: str) -> str:
        if v not in BOUNDARY_BASIS:
            raise ValueError(f"boundary basis not allowed: {v}")
        return v

    @model_validator(mode="after")
    def _provenance_for_basis(self) -> TrustBoundary:
        if self.basis != "OBSERVED" and not self.provenance:
            raise ValueError("non-OBSERVED boundary requires provenance")
        return self


class EntryPoint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    entry_id: str = Field(...)
    route_id: str = Field(default="", max_length=320)
    method: str = Field(default="", max_length=12)
    path: str = Field(default="", max_length=512)
    handler: str = Field(default="", max_length=320)

    @field_validator("entry_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("entry_id must be kebab-case")
        return v


class ExitPoint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    exit_id: str = Field(...)
    sink_id: str = Field(default="", max_length=320)
    kind: str = Field(default="", max_length=60)

    @field_validator("exit_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("exit_id must be kebab-case")
        return v


class SystemModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(default="", max_length=200)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    actors: tuple[SystemActor, ...] = ()
    components: tuple[SystemComponent, ...] = ()
    assets: tuple[SystemAsset, ...] = ()
    stores: tuple[SystemDataStore, ...] = ()
    processes: tuple[SystemProcess, ...] = ()
    flows: tuple[SystemDataFlow, ...] = ()
    boundaries: tuple[TrustBoundary, ...] = ()
    entries: tuple[EntryPoint, ...] = ()
    exits: tuple[ExitPoint, ...] = ()
    coverage: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()


class AttackSurfaceElement(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    element_id: str = Field(...)
    category: str = Field(...)
    asset_id: str = Field(default="", max_length=200)
    project_id: str = Field(default="", max_length=200)
    snapshot_id: str = Field(default="", max_length=160)
    component_id: str = Field(default="", max_length=320)
    route_id: str = Field(default="", max_length=320)
    symbol_id: str = Field(default="", max_length=320)
    evidence_ids: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)
    coverage: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()

    @field_validator("element_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("element_id must be kebab-case")
        return v

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        if v not in SURFACE_CATEGORIES:
            raise ValueError(f"surface category not allowed: {v}")
        return v


class AttackSurfaceRelation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    from_id: str = Field(..., min_length=1, max_length=320)
    to_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(default="reaches", max_length=60)


class AttackSurface(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(default="", max_length=200)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    elements: tuple[AttackSurfaceElement, ...] = ()
    relations: tuple[AttackSurfaceRelation, ...] = ()
    completeness: str = Field(default="UNKNOWN", max_length=24)
    coverage: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()


class SecurityControl(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    control_id: str = Field(...)
    kind: str = Field(...)
    status: str = Field(...)
    evidence_ids: tuple[str, ...] = ()
    protects: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("control_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("control_id must be kebab-case")
        return v

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in CONTROL_KINDS:
            raise ValueError(f"control kind not allowed: {v}")
        return v

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in CONTROL_STATUS:
            raise ValueError(f"control status not allowed: {v}")
        return v


class ControlEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    control_id: str = Field(..., min_length=1, max_length=320)
    evidence_ids: tuple[str, ...] = ()


class ControlCoverage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    category: str = Field(..., min_length=1, max_length=60)
    relevant_controls: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    verification_requirements: tuple[str, ...] = ()


class ThreatScenario(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    scenario_id: str = Field(...)
    method: str = Field(..., min_length=1, max_length=40)
    category: str = Field(..., min_length=1, max_length=60)
    subject: str = Field(..., min_length=1, max_length=320)
    preconditions: tuple[str, ...] = ()
    attack_goal: str = Field(default="", max_length=500)
    affected_assets: tuple[str, ...] = ()
    affected_components: tuple[str, ...] = ()
    affected_flows: tuple[str, ...] = ()
    trust_boundary_crossings: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    hypothesis_status: str = Field(default="HYPOTHESIZED", max_length=24)
    verification_requirements: tuple[str, ...] = ()
    possible_controls: tuple[str, ...] = ()
    coverage: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()

    @field_validator("scenario_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("scenario_id must be kebab-case")
        return v

    @field_validator("hypothesis_status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in HYPOTHESIS_STATUS:
            raise ValueError(f"hypothesis status not allowed: {v}")
        return v


class ThreatHypothesis(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    hypothesis_id: str = Field(...)
    statement: str = Field(..., min_length=1, max_length=1000)
    scenario_id: str = Field(default="", max_length=320)
    status: str = Field(default="HYPOTHESIZED", max_length=24)

    @field_validator("hypothesis_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("hypothesis_id must be kebab-case")
        return v

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in HYPOTHESIS_STATUS:
            raise ValueError(f"hypothesis status not allowed: {v}")
        return v


class AttackPath(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path_id: str = Field(...)
    actor_id: str = Field(default="", max_length=320)
    entry_id: str = Field(default="", max_length=320)
    nodes: tuple[str, ...] = ()
    boundary_crossings: tuple[str, ...] = ()
    target_asset_id: str = Field(default="", max_length=320)
    path_class: str = Field(default="POSSIBLE_PATH", max_length=24)
    evidence_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @field_validator("path_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("path_id must be kebab-case")
        return v

    @field_validator("path_class")
    @classmethod
    def _class(cls, v: str) -> str:
        if v not in PATH_CLASSES:
            raise ValueError(f"path class not allowed: {v}")
        return v


class Mitigation(BaseModel):
    """Planning information only. Never applied, committed, or deployed."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    mitigation_id: str = Field(...)
    control: str = Field(..., min_length=1, max_length=120)
    rationale: str = Field(default="", max_length=500)
    affected_component: str = Field(default="", max_length=320)
    evidence_needed: tuple[str, ...] = ()
    verification_needed: tuple[str, ...] = ()

    @field_validator("mitigation_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("mitigation_id must be kebab-case")
        return v


class ThreatVerificationHandoff(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    handoff_id: str = Field(...)
    threat_scenario_id: str = Field(..., min_length=1, max_length=320)
    target_snapshot_id: str = Field(..., min_length=1, max_length=160)
    target_component: str = Field(default="", max_length=320)
    target_entrypoint: str = Field(default="", max_length=320)
    required_evidence: tuple[str, ...] = ()
    verification_method: str = Field(default="static_confirmation", max_length=60)
    safety_level: str = Field(default="passive", max_length=24)
    success_criteria: str = Field(default="", max_length=500)
    refutation_criteria: str = Field(default="", max_length=500)
    compatible_snapshots: tuple[str, ...] = ()

    @field_validator("handoff_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("handoff_id must be kebab-case")
        return v


class ThreatAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    scenario_count: int = Field(default=0, ge=0)
    surface_count: int = Field(default=0, ge=0)
    boundary_count: int = Field(default=0, ge=0)
    control_count: int = Field(default=0, ge=0)
    coverage: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()


class ModelCoverage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    endpoints: str = Field(default="UNKNOWN", max_length=24)
    boundaries: str = Field(default="UNKNOWN", max_length=24)
    flows: str = Field(default="UNKNOWN", max_length=24)
    assets: str = Field(default="UNKNOWN", max_length=24)


class ThreatMethod(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    method_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(...)
    categories: tuple[str, ...] = ()
    description: str = Field(default="", max_length=1000)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("method_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("method_id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VER_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v


class ThreatRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    rule_id: str = Field(...)
    method: str = Field(..., min_length=1, max_length=40)
    category: str = Field(..., min_length=1, max_length=60)
    subject_kind: str = Field(default="component", max_length=40)
    description: str = Field(default="", max_length=500)

    @field_validator("rule_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("rule_id must be kebab-case")
        return v


class ThreatPattern(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    pattern_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=160)
    indicators: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("pattern_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("pattern_id must be kebab-case")
        return v


class ThreatCategory(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    category_id: str = Field(...)
    method: str = Field(..., min_length=1, max_length=40)
    name: str = Field(..., min_length=1, max_length=120)
    applicable_subjects: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @field_validator("category_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("category_id must be kebab-case")
        return v


class ThreatDeltaEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: str = Field(...)
    subject_id: str = Field(default="", max_length=320)
    detail: str = Field(default="", max_length=500)

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in DELTA_KINDS:
            raise ValueError(f"delta kind not allowed: {v}")
        return v


class ThreatModelDelta(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    base_snapshot_id: str = Field(..., min_length=1, max_length=160)
    target_snapshot_id: str = Field(..., min_length=1, max_length=160)
    entries: tuple[ThreatDeltaEntry, ...] = ()
    coverage_change: str = Field(default="", max_length=200)
    limitations: tuple[str, ...] = ()


class ThreatTemplateConfig(BaseModel):
    """Declarative starter: methods + scope + declared assets/boundaries.
    Planning input only; never executable."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    template_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(...)
    methods: tuple[str, ...] = ()
    scope_assets: tuple[str, ...] = ()
    declared_boundaries: tuple[dict[str, Any], ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("template_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("template_id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VER_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @staticmethod
    def digest_of(template: ThreatTemplateConfig) -> str:
        canonical = json.dumps(template.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


class ThreatModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    model_id: str = Field(...)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(default="", max_length=200)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    methods: tuple[str, ...] = ()
    system: SystemModel | None = None
    surface: AttackSurface | None = None
    scenarios: tuple[ThreatScenario, ...] = ()
    attack_paths: tuple[AttackPath, ...] = ()
    controls: tuple[SecurityControl, ...] = ()
    mitigations: tuple[Mitigation, ...] = ()
    handoffs: tuple[ThreatVerificationHandoff, ...] = ()
    assessment: ThreatAssessment = Field(default_factory=ThreatAssessment)
    coverage: ModelCoverage = Field(default_factory=ModelCoverage)
    limitations: tuple[str, ...] = ()
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    model_digest: str = Field(default="", max_length=128)

    @field_validator("model_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("model_id must be kebab-case")
        return v
