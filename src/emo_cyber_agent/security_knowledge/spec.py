"""Security knowledge domain — POST-RC-011.

Scoped, provenance-preserving security knowledge and regression
context. Memory is evidence-indexing and regression context, not
truth: historical records never become authority, current
evidence, or Finding state.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_HEX_RE = re.compile(r"^[0-9a-f]{16,128}$")

KNOWLEDGE_SCHEMA_VERSION = "1.0"

# The only persistable categories. Everything else is rejected.
PERSISTABLE_CATEGORIES: tuple[str, ...] = (
    "OBSERVED_FACT",
    "EVIDENCE_SUMMARY",
    "VERIFICATION_OUTCOME",
    "THREAT_MODEL_OBSERVATION",
    "ATTACK_SURFACE_OBSERVATION",
    "CHANGE_REGRESSION_SIGNAL",
    "TOOL_OBSERVATION",
    "CODE_INTELLIGENCE_OBSERVATION",
    "SECURITY_CONTROL_OBSERVATION",
)

SCOPE_KINDS: tuple[str, ...] = ("SNAPSHOT_BOUND", "RANGE_BOUND", "PROJECT_LIFETIME")

REGRESSION_STATES: tuple[str, ...] = (
    "NEW", "PERSISTING", "CHANGED", "DISAPPEARED",
    "REINTRODUCED", "INDETERMINATE", "NOT_COMPARABLE",
)

COMPARATOR_RESULTS: tuple[str, ...] = (
    "IDENTICAL", "CHANGED", "NEW", "MISSING", "INDETERMINATE", "INCOMPATIBLE",
)

PRECEDENCE_STATES: tuple[str, ...] = ("CONTRADICTED", "SUPERSEDED", "STALE", "CURRENT")

STALENESS_STATES: tuple[str, ...] = ("FRESH_FOR_SCOPE", "STALE", "INCOMPATIBLE", "UNKNOWN")

VERIFICATION_RESULTS: tuple[str, ...] = ("SUPPORTED", "REFUTED", "INCONCLUSIVE", "BLOCKED", "EXPIRED")

TRUST_LEVELS: tuple[str, ...] = ("untrusted", "UNTRUSTED_SUGGESTION", "untrusted-external", "quarantined")

# Vocabulary that must never appear as knowledge/regression semantics.
KNOWLEDGE_VERDICT_TOKENS: tuple[str, ...] = (
    "resolved", "confirmed", "vulnerable", "fixed", "safe",
    "severity", "exploitable", "remediated",
)


class PackTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"


def _kebab(value: str, field: str) -> str:
    if not _ID_RE.match(value):
        raise ValueError(f"{field} must be kebab-case")
    return value


def assert_no_knowledge_verdicts(*texts: str) -> None:
    from emo_cyber_agent.security_knowledge.errors import KnowledgeError, KnowledgeErrorCode

    for text in texts:
        lowered = (text or "").lower()
        for token in KNOWLEDGE_VERDICT_TOKENS:
            if re.search(rf"(?<![\w.:/-]){re.escape(token)}(?![\w-])", lowered):
                raise KnowledgeError(KnowledgeErrorCode.VERDICT_CAPPED, f"verdict vocabulary denied: {token}")


class KnowledgeScope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    snapshot_id: str = Field(default="", max_length=160)
    base_snapshot_id: str = Field(default="", max_length=160)
    scope_kind: str = Field(default="SNAPSHOT_BOUND", max_length=24)

    @field_validator("scope_kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in SCOPE_KINDS:
            raise ValueError(f"scope kind not allowed: {v}")
        return v


class KnowledgeProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    origin: str = Field(..., min_length=1, max_length=160)
    collector: str = Field(default="", max_length=160)
    normalization_version: str = Field(default="1.0", max_length=40)
    schema_version: str = Field(default=KNOWLEDGE_SCHEMA_VERSION, max_length=40)
    evidence_ids: tuple[str, ...] = ()
    parent_digests: tuple[str, ...] = ()


class KnowledgeRetention(BaseModel):
    """Retention metadata only. No scheduler, no automated deletion."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    retention_class: str = Field(default="audit-lifetime", max_length=60)
    created_at: str = Field(default="", max_length=60)
    expires_at: str = Field(default="", max_length=60)
    legal_hold: bool = False
    retention_reason: str = Field(default="", max_length=300)


class KnowledgeRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    record_id: str = Field(...)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    snapshot_id: str = Field(default="", max_length=160)
    scope_kind: str = Field(default="SNAPSHOT_BOUND", max_length=24)
    source_type: str = Field(..., min_length=1, max_length=80)
    source_id: str = Field(..., min_length=1, max_length=320)
    category: str = Field(...)
    created_from_evidence_ids: tuple[str, ...] = ()
    content: dict[str, Any] = Field(default_factory=dict)
    content_digest: str = Field(default="", max_length=128)
    related_finding_id: str = Field(default="", max_length=160)
    verification_ref: str = Field(default="", max_length=160)
    regression_key: str = Field(default="", max_length=320)
    trust_level: str = Field(default="untrusted", max_length=40)
    provenance: KnowledgeProvenance | None = None
    digest: str = Field(default="", max_length=128)
    schema_version: str = Field(default=KNOWLEDGE_SCHEMA_VERSION, max_length=40)
    retention: KnowledgeRetention = Field(default_factory=KnowledgeRetention)

    @field_validator("record_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "record_id")

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        if v not in PERSISTABLE_CATEGORIES:
            raise ValueError(f"category not persistable: {v}")
        return v

    @field_validator("scope_kind")
    @classmethod
    def _scope_kind(cls, v: str) -> str:
        if v not in SCOPE_KINDS:
            raise ValueError(f"scope kind not allowed: {v}")
        return v

    @field_validator("trust_level")
    @classmethod
    def _trust(cls, v: str) -> str:
        if v not in TRUST_LEVELS:
            raise ValueError(f"trust level not allowed: {v}")
        return v

    @model_validator(mode="after")
    def _mandatory_identity(self) -> KnowledgeRecord:
        if not self.audit_id or not self.project_id:
            raise ValueError("knowledge record requires audit_id and project_id")
        if self.provenance is None:
            raise ValueError("knowledge record requires provenance")
        return self


class KnowledgeReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    record_id: str = Field(...)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    snapshot_id: str = Field(default="", max_length=160)
    digest: str = Field(default="", max_length=128)

    @field_validator("record_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "record_id")


class EvidenceFingerprint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    fingerprint_id: str = Field(...)
    identity_kind: str = Field(...)
    project_id: str = Field(..., min_length=1, max_length=200)
    object_type: str = Field(..., min_length=1, max_length=80)
    object_identity: str = Field(..., min_length=1, max_length=320)
    snapshot_semantics: str = Field(default="", max_length=160)
    source: str = Field(..., min_length=1, max_length=160)
    security_property: str = Field(..., min_length=1, max_length=160)
    facts_digest: str = Field(default="", max_length=128)
    digest: str = Field(default="", max_length=128)

    @field_validator("fingerprint_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "fingerprint_id")

    @field_validator("identity_kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in ("SNAPSHOT_IDENTITY", "STRUCTURAL_IDENTITY", "REGRESSION_IDENTITY"):
            raise ValueError(f"identity kind not allowed: {v}")
        return v


class ObservationFingerprint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    fingerprint_id: str = Field(...)
    identity_kind: str = Field(...)
    project_id: str = Field(..., min_length=1, max_length=200)
    object_type: str = Field(..., min_length=1, max_length=80)
    object_identity: str = Field(..., min_length=1, max_length=320)
    snapshot_semantics: str = Field(default="", max_length=160)
    source: str = Field(..., min_length=1, max_length=160)
    security_property: str = Field(..., min_length=1, max_length=160)
    facts_digest: str = Field(default="", max_length=128)
    digest: str = Field(default="", max_length=128)

    @field_validator("fingerprint_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "fingerprint_id")

    @field_validator("identity_kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in ("SNAPSHOT_IDENTITY", "STRUCTURAL_IDENTITY", "REGRESSION_IDENTITY"):
            raise ValueError(f"identity kind not allowed: {v}")
        return v


class SecurityRegressionRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    regression_id: str = Field(...)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    base_snapshot_id: str = Field(default="", max_length=160)
    target_snapshot_id: str = Field(default="", max_length=160)
    regression_key: str = Field(..., min_length=1, max_length=320)
    before_digest: str = Field(default="", max_length=128)
    after_digest: str = Field(default="", max_length=128)
    state: str = Field(...)
    evidence_ids: tuple[str, ...] = ()
    provenance: KnowledgeProvenance | None = None
    digest: str = Field(default="", max_length=128)

    @field_validator("regression_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "regression_id")

    @field_validator("state")
    @classmethod
    def _state(cls, v: str) -> str:
        if v not in REGRESSION_STATES:
            raise ValueError(f"regression state not allowed: {v}")
        return v


class RegressionComparison(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    base_key: str = Field(default="", max_length=320)
    target_key: str = Field(default="", max_length=320)
    result: str = Field(...)
    reason_codes: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    coverage: str = Field(default="complete", max_length=24)
    limitations: tuple[str, ...] = ()

    @field_validator("result")
    @classmethod
    def _result(cls, v: str) -> str:
        if v not in COMPARATOR_RESULTS:
            raise ValueError(f"comparator result not allowed: {v}")
        return v


class KnowledgeCoverage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    completeness: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()


class KnowledgeAccess(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    allowed_operations: tuple[str, ...] = ()
    reason: str = Field(default="", max_length=300)


class VerificationOutcomeRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    verification_id: str = Field(...)
    target_snapshot_id: str = Field(..., min_length=1, max_length=160)
    method: str = Field(..., min_length=1, max_length=60)
    criteria: str = Field(default="", max_length=500)
    result: str = Field(...)
    evidence_ids: tuple[str, ...] = ()
    provenance: KnowledgeProvenance | None = None

    @field_validator("verification_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "verification_id")

    @field_validator("result")
    @classmethod
    def _result(cls, v: str) -> str:
        if v not in VERIFICATION_RESULTS:
            raise ValueError(f"verification result not allowed: {v}")
        return v


class ExternalKnowledgeEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source: str = Field(..., min_length=1, max_length=160)
    source_version: str = Field(default="", max_length=60)
    retrieved_at: str = Field(default="", max_length=60)
    external_id: str = Field(..., min_length=1, max_length=320)
    source_url: str = Field(default="", max_length=512)
    content_digest: str = Field(default="", max_length=128)
    trust_level: str = Field(default="untrusted-external", max_length=40)
    license: str = Field(default="", max_length=160)
    provenance: dict[str, Any] = Field(default_factory=dict)
    content_redacted: dict[str, Any] = Field(default_factory=dict)

    @field_validator("trust_level")
    @classmethod
    def _trust(cls, v: str) -> str:
        if v not in ("untrusted-external", "quarantined"):
            raise ValueError("external knowledge is never trusted on ingest")
        return v


class KnowledgeTemplateConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    template_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(...)
    allowed_categories: tuple[str, ...] = ()
    default_retention_class: str = Field(default="audit-lifetime", max_length=60)
    scope_rules: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("template_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "template_id")

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        import re as _re

        if not _re.match(r"^\d+\.\d+\.\d+$", v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @staticmethod
    def digest_of(template: KnowledgeTemplateConfig) -> str:
        from emo_cyber_agent.threat_modeling.spec import canonical_digest

        return canonical_digest(template.model_dump(mode="json"))
