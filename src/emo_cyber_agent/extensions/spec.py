"""Extension contract — POST-RC-014.

The extension layer describes *what exists*, never *what is allowed*.
Every model here is frozen, typed, extra-forbidden and canonicalized:
identity comes from semantic metadata plus artifact identity, never
from an install path, an import order, a wall clock or a random id.

Four separations are structural, not documented:
  discovery  != trust       (metadata is found, trust is evaluated)
  installation != permission (pip installs; Core grants nothing)
  registration != execution authority (a registry entry runs nothing)
  metadata   != security verdict (a manifest is not a Finding)
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.core.repository import normalize_path
from emo_cyber_agent.threat_modeling.spec import canonical_digest

__all__ = [
    # constants
    "ALLOWED_DECLARED_CAPABILITIES",
    "ALLOWED_TRANSITIONS",
    "CAPABILITY_ALLOWED_FOR",
    "CONTRACT_VERSION",
    "DATA_ACCESS_TOKENS",
    "DECLARATIVE_TYPES",
    "EXECUTABLE_TYPES",
    "EXTENSION_API_VERSION",
    "EXTENSION_TYPES",
    "FORBIDDEN_DECLARATIONS",
    "FORBIDDEN_SECRET_DECLARATIONS",
    "IDENTITY_EXCLUDED_FIELDS",
    "SCHEMA_VERSION",
    "SELF_DECLARED_TRUST_KEYS",
    # enums
    "DatasetClassification",
    "ExtensionCapabilityDeclaration",
    "ExtensionConflictKind",
    "ExtensionDependency",
    "ExtensionDependencyType",
    "ExtensionEntrypoint",
    "ExtensionEntrypointKind",
    "ExtensionHealth",
    "ExtensionHealthStatus",
    "ExtensionIdentity",
    "ExtensionLifecycle",
    "ExtensionManifest",
    "ExtensionProvenance",
    "ExtensionResource",
    "ExtensionResourceKind",
    "ExtensionSecurityProfile",
    "ExtensionSourceClass",
    "ExtensionTrust",
    "ExtensionTrustState",
    "ExtensionType",
    "ExtensionVersion",
    "NetworkRequirement",
    "ProcessRequirement",
    "ProvenanceStatus",
    "SecretDeclaration",
    "VersionPolicy",
    # functions
    "extension_types",
    "manifest_identity_digest",
    "parse_version",
    "split_constraint",
    "version_key",
]

EXTENSION_API_VERSION = "1.0"
"""Host API version this layer implements. Breaking contract changes bump it."""

CONTRACT_VERSION = "1.0"
"""Execution-contract version advertised to executable extensions."""

SCHEMA_VERSION = "1.0"
"""Manifest schema version advertised through compatibility checks."""

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_VER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_API_RE = re.compile(r"^\d+\.\d+$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_FEATURE_RE = re.compile(r"^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)*$")
_ENTRY_TARGET_RE = re.compile(r"^[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)*:[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)*$")

# Fields that never enter identity: none of the manifest's own fields are
# install-path, ordering, clock or randomness dependent, so identity is the
# full canonical payload minus the digest itself (self-reference excluded).
IDENTITY_EXCLUDED_FIELDS: frozenset[str] = frozenset({"digest"})


# ---------------------------------------------------------------------------
# Closed taxonomies
# ---------------------------------------------------------------------------


class ExtensionType(StrEnum):
    """Closed extension taxonomy. Unknown types never load partially."""

    SKILL = "skill"
    SKILL_PACK = "skill_pack"
    TASK = "task"
    PLAYBOOK = "playbook"
    REPORT_TEMPLATE = "report_template"
    TOOL_PACK = "tool_pack"
    VERIFICATION_STRATEGY = "verification_strategy"
    VERIFICATION_ADAPTER = "verification_adapter"
    THREAT_METHOD = "threat_method"
    THREAT_RULESET = "threat_ruleset"
    EVALUATION_DATASET = "evaluation_dataset"


EXTENSION_TYPES: tuple[str, ...] = tuple(member.value for member in ExtensionType)

DECLARATIVE_TYPES: frozenset[str] = frozenset(
    {
        ExtensionType.SKILL.value,
        ExtensionType.SKILL_PACK.value,
        ExtensionType.TASK.value,
        ExtensionType.PLAYBOOK.value,
        ExtensionType.REPORT_TEMPLATE.value,
        ExtensionType.THREAT_METHOD.value,
        ExtensionType.THREAT_RULESET.value,
        ExtensionType.EVALUATION_DATASET.value,
    }
)

EXECUTABLE_TYPES: frozenset[str] = frozenset(
    {
        ExtensionType.TOOL_PACK.value,
        ExtensionType.VERIFICATION_ADAPTER.value,
        ExtensionType.VERIFICATION_STRATEGY.value,
    }
)


def extension_types() -> tuple[str, ...]:
    """Deterministic extension type list (never an import-order artifact)."""
    return EXTENSION_TYPES


class ExtensionTrustState(StrEnum):
    """Closed trust vocabulary. Only the loader/catalog assigns it."""

    BUILTIN_TRUSTED = "builtin_trusted"
    OFFICIAL_TRUSTED = "official_trusted"
    VERIFIED_EXTERNAL = "verified_external"
    UNTRUSTED = "untrusted"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"


TRUSTED_STATES: frozenset[str] = frozenset(
    {
        ExtensionTrustState.BUILTIN_TRUSTED.value,
        ExtensionTrustState.OFFICIAL_TRUSTED.value,
        ExtensionTrustState.VERIFIED_EXTERNAL.value,
    }
)


class ExtensionSourceClass(StrEnum):
    """Where the extension came from. Determines starting trust."""

    BUILTIN = "builtin"
    OFFICIAL_EXTERNAL = "official_external"
    THIRD_PARTY = "third_party"
    LOCAL_DEVELOPMENT = "local_development"


class ExtensionLifecycle(StrEnum):
    """Host-controlled lifecycle. An extension never transitions itself."""

    DISCOVERED = "discovered"
    VALIDATED = "validated"
    COMPATIBLE = "compatible"
    TRUST_EVALUATED = "trust_evaluated"
    REGISTERED = "registered"
    LOADABLE = "loadable"
    LOADED = "loaded"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"
    UNLOADED = "unloaded"


ALLOWED_TRANSITIONS: dict[ExtensionLifecycle, tuple[ExtensionLifecycle, ...]] = {
    ExtensionLifecycle.DISCOVERED: (ExtensionLifecycle.VALIDATED, ExtensionLifecycle.QUARANTINED, ExtensionLifecycle.REJECTED),
    ExtensionLifecycle.VALIDATED: (ExtensionLifecycle.COMPATIBLE, ExtensionLifecycle.QUARANTINED, ExtensionLifecycle.REJECTED),
    ExtensionLifecycle.COMPATIBLE: (ExtensionLifecycle.TRUST_EVALUATED, ExtensionLifecycle.QUARANTINED, ExtensionLifecycle.REJECTED),
    ExtensionLifecycle.TRUST_EVALUATED: (ExtensionLifecycle.REGISTERED, ExtensionLifecycle.QUARANTINED, ExtensionLifecycle.REJECTED),
    ExtensionLifecycle.REGISTERED: (ExtensionLifecycle.LOADABLE, ExtensionLifecycle.QUARANTINED, ExtensionLifecycle.REJECTED),
    ExtensionLifecycle.LOADABLE: (ExtensionLifecycle.LOADED, ExtensionLifecycle.QUARANTINED, ExtensionLifecycle.REJECTED),
    ExtensionLifecycle.LOADED: (ExtensionLifecycle.UNLOADED, ExtensionLifecycle.QUARANTINED),
    ExtensionLifecycle.UNLOADED: (ExtensionLifecycle.LOADABLE, ExtensionLifecycle.QUARANTINED),
    ExtensionLifecycle.QUARANTINED: (ExtensionLifecycle.REJECTED,),
    ExtensionLifecycle.REJECTED: (),
}


class ExtensionDependencyType(StrEnum):
    CONTENT = "content"
    CONTRACT = "contract"
    IMPLEMENTATION = "implementation"


class ExtensionEntrypointKind(StrEnum):
    DECLARATIVE = "declarative"
    IMPLEMENTATION = "implementation"


class ExtensionResourceKind(StrEnum):
    SCHEMA = "schema"
    TEMPLATE = "template"
    RULE = "rule"
    FIXTURE = "fixture"
    DOCUMENTATION = "documentation"
    STATIC_METADATA = "static_metadata"


class NetworkRequirement(StrEnum):
    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"


class ProcessRequirement(StrEnum):
    NONE = "none"
    TOOL_EXECUTOR_ONLY = "tool_executor_only"


class SecretDeclaration(StrEnum):
    USES_EXISTING_REDACTION = "uses_existing_redaction"
    SYNTHETIC_TEST_CREDENTIALS = "synthetic_test_credentials"


class ExtensionHealthStatus(StrEnum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"


class DatasetClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    BLIND = "blind"
    HOLDOUT = "holdout"


class ProvenanceStatus(StrEnum):
    MISSING = "missing"
    PARTIAL = "partial"
    PRESENT = "present"


class ExtensionConflictKind(StrEnum):
    DUPLICATE_IDENTITY = "duplicate_identity"
    PROVIDER_CONFLICT = "provider_conflict"
    VERSION_AMBIGUOUS = "version_ambiguous"
    DEPENDENCY_CYCLE = "dependency_cycle"
    DEPENDENCY_MISSING = "dependency_missing"
    DEPENDENCY_INCOMPATIBLE = "dependency_incompatible"


class VersionPolicy(StrEnum):
    EXACT = "exact"
    HIGHEST_COMPATIBLE = "highest_compatible"


# ---------------------------------------------------------------------------
# Capability declarations and forbidden declarations
# ---------------------------------------------------------------------------


class ExtensionDeclaredCapability(StrEnum):
    """Closed declaration vocabulary. Declaring is not being granted."""

    SKILL = "skill"
    SKILL_PACK = "skill_pack"
    TASK = "task"
    PLAYBOOK = "playbook"
    REPORT_TEMPLATE = "report_template"
    TOOL_PACK = "tool_pack"
    VERIFICATION_STRATEGY = "verification_strategy"
    VERIFICATION_ADAPTER = "verification_adapter"
    THREAT_METHOD = "threat_method"
    THREAT_RULESET = "threat_ruleset"
    EVALUATION_DATASET = "evaluation_dataset"


ALLOWED_DECLARED_CAPABILITIES: tuple[str, ...] = tuple(member.value for member in ExtensionDeclaredCapability)

CAPABILITY_ALLOWED_FOR: dict[str, tuple[str, ...]] = {
    ExtensionType.SKILL.value: (ExtensionType.SKILL.value,),
    ExtensionType.SKILL_PACK.value: (ExtensionType.SKILL_PACK.value, ExtensionType.SKILL.value),
    ExtensionType.TASK.value: (ExtensionType.TASK.value,),
    ExtensionType.PLAYBOOK.value: (ExtensionType.PLAYBOOK.value,),
    ExtensionType.REPORT_TEMPLATE.value: (ExtensionType.REPORT_TEMPLATE.value,),
    ExtensionType.TOOL_PACK.value: (ExtensionType.TOOL_PACK.value,),
    ExtensionType.VERIFICATION_STRATEGY.value: (ExtensionType.VERIFICATION_STRATEGY.value,),
    ExtensionType.VERIFICATION_ADAPTER.value: (ExtensionType.VERIFICATION_ADAPTER.value,),
    ExtensionType.THREAT_METHOD.value: (ExtensionType.THREAT_METHOD.value,),
    ExtensionType.THREAT_RULESET.value: (ExtensionType.THREAT_RULESET.value, ExtensionType.THREAT_METHOD.value),
    ExtensionType.EVALUATION_DATASET.value: (ExtensionType.EVALUATION_DATASET.value,),
}

FORBIDDEN_DECLARATIONS: frozenset[str] = frozenset(
    {
        "grant",
        "write",
        "delete",
        "execute_remote",
        "privilege_escalation",
        "policy_override",
        "finding_confirm",
        "finding_resolve",
        "auto_remediate",
        "auto_approve",
        "shell",
        "arbitrary_code",
        "global_memory",
        "credential_access",
    }
)

FORBIDDEN_SECRET_DECLARATIONS: frozenset[str] = frozenset(
    {
        "raw_credential_access",
        "secret_export",
        "token_harvesting",
    }
)

FORBIDDEN_PROCESS_DECLARATIONS: frozenset[str] = frozenset(
    {
        "arbitrary_process",
        "shell",
    }
)

DATA_ACCESS_TOKENS: tuple[str, ...] = (
    "audit_input",
    "build_metadata",
    "documentation",
    "fixture_content",
    "static_metadata",
)

SELF_DECLARED_TRUST_KEYS: frozenset[str] = frozenset(
    {
        "approved",
        "authority",
        "grant",
        "granted",
        "self_trusted",
        "trust",
        "trust_state",
        "trusted",
    }
)

# Tokens whose *standalone* mention inside free text is an authority claim.
# Dotted or slashed identifiers (``code.execute``, ``repo/write``) stay data.
_AUTHORITY_SCAN_TOKENS: tuple[str, ...] = tuple(sorted(FORBIDDEN_DECLARATIONS | FORBIDDEN_SECRET_DECLARATIONS | FORBIDDEN_PROCESS_DECLARATIONS))

_ENTRY_FORBIDDEN_KINDS: dict[str, frozenset[str]] = {
    ExtensionType.SKILL.value: frozenset({ExtensionEntrypointKind.IMPLEMENTATION.value}),
    ExtensionType.SKILL_PACK.value: frozenset({ExtensionEntrypointKind.IMPLEMENTATION.value}),
    ExtensionType.TASK.value: frozenset({ExtensionEntrypointKind.IMPLEMENTATION.value}),
    ExtensionType.PLAYBOOK.value: frozenset({ExtensionEntrypointKind.IMPLEMENTATION.value}),
    ExtensionType.REPORT_TEMPLATE.value: frozenset({ExtensionEntrypointKind.IMPLEMENTATION.value}),
    ExtensionType.THREAT_METHOD.value: frozenset({ExtensionEntrypointKind.IMPLEMENTATION.value}),
    ExtensionType.THREAT_RULESET.value: frozenset({ExtensionEntrypointKind.IMPLEMENTATION.value}),
    ExtensionType.EVALUATION_DATASET.value: frozenset({ExtensionEntrypointKind.IMPLEMENTATION.value}),
    ExtensionType.VERIFICATION_ADAPTER.value: frozenset({ExtensionEntrypointKind.DECLARATIVE.value}),
}


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------


def split_constraint(part: str) -> tuple[str, str]:
    """Split ``>=1.2.3`` into ``(">=", "1.2.3")``; a bare version is exact."""
    raw = part.strip()
    operator = "".join(ch for ch in raw if not ch.isdigit() and ch != ".").strip()
    operand = raw[len(operator) :].strip()
    if not operator:
        return "==", raw
    return operator, operand


def parse_version(text: str) -> tuple[int, int, int]:
    """Parse a strict ``X.Y.Z`` version into a comparable key."""
    if not _VER_RE.match(text or ""):
        raise ValueError(f"version must be semver X.Y.Z: {text!r}")
    major, minor, patch = (int(part) for part in text.split("."))
    return (major, minor, patch)


def version_key(text: str) -> tuple[int, int, int]:
    """Deterministic ordering key. Never alphabetical, never wall-clock."""
    return parse_version(text)


def manifest_identity_digest(payload: dict[str, Any]) -> str:
    """Canonical identity digest over semantic metadata only.

    Independent of install path, import ordering, wall clock, random
    identifiers and filesystem ordering by construction."""
    return canonical_digest(payload)


# ---------------------------------------------------------------------------
# Value models
# ---------------------------------------------------------------------------


class ExtensionVersion(BaseModel):
    """Typed semantic version used by the resolver."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    major: int = Field(ge=0)
    minor: int = Field(ge=0)
    patch: int = Field(ge=0)

    @classmethod
    def parse(cls, text: str) -> ExtensionVersion:
        major, minor, patch = parse_version(text)
        return cls(major=major, minor=minor, patch=patch)

    @property
    def text(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


class ExtensionIdentity(BaseModel):
    """Stable identity: id + version + type. No path, no clock."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    extension_id: str = Field(..., min_length=3, max_length=80)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(..., min_length=5, max_length=32)
    extension_type: ExtensionType

    @field_validator("extension_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError("extension_id must be kebab-case")
        return value

    @field_validator("version")
    @classmethod
    def _version(cls, value: str) -> str:
        parse_version(value)
        return value


class ExtensionDependency(BaseModel):
    """A dependency is a claim about *content*, never an authority grant."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    extension_id: str = Field(..., min_length=3, max_length=80)
    version_constraint: str = Field(default="*", max_length=120)
    dependency_type: ExtensionDependencyType = ExtensionDependencyType.CONTENT
    required: bool = True

    @field_validator("extension_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError("dependency extension_id must be kebab-case")
        return value

    @field_validator("version_constraint")
    @classmethod
    def _constraint(cls, value: str) -> str:
        text = (value or "").strip() or "*"
        if text == "*":
            return text
        for part in text.split(","):
            part = part.strip()
            if not part:
                raise ValueError("empty constraint segment")
            operator, operand = split_constraint(part)
            if operator not in (">=", "<=", "==", "!=", ">", "<", "~="):
                raise ValueError(f"unsupported constraint operator: {operator!r}")
            if operator == "~=":
                if not re.match(r"^\d+\.\d+$", operand):
                    raise ValueError("~= constraint needs X.Y")
            elif not _VER_RE.match(operand):
                raise ValueError("constraint operand must be semver X.Y.Z")
        return text


class ExtensionCapabilityDeclaration(BaseModel):
    """Declarations only. Nothing here becomes a Policy capability."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    declares: tuple[ExtensionDeclaredCapability, ...] = Field(default_factory=tuple)
    provides_feature: tuple[str, ...] = Field(default_factory=tuple)
    optional_feature: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("provides_feature", "optional_feature")
    @classmethod
    def _features(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not _FEATURE_RE.match(value):
                raise ValueError(f"feature token must be UPPER.DOTTED: {value!r}")
        return values


class ExtensionCompatibility(BaseModel):
    """Explicit compatibility contract. No latest-compatible guessing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    emo_api_min: str = Field(default="1.0", max_length=16)
    emo_api_max: str = Field(default="", max_length=16)
    schema_versions: tuple[str, ...] = Field(default_factory=tuple)
    required_features: tuple[str, ...] = Field(default_factory=tuple)
    optional_features: tuple[str, ...] = Field(default_factory=tuple)
    python_requires: str = Field(default=">=3.11", max_length=64)
    platforms: tuple[str, ...] = Field(default_factory=lambda: ("linux", "darwin", "win32"))

    @field_validator("emo_api_min")
    @classmethod
    def _api_min(cls, value: str) -> str:
        if not _API_RE.match(value):
            raise ValueError("emo_api_min must look like X.Y")
        return value

    @field_validator("emo_api_max")
    @classmethod
    def _api_max(cls, value: str) -> str:
        if value and not _API_RE.match(value):
            raise ValueError("emo_api_max must look like X.Y")
        return value

    @field_validator("required_features", "optional_features")
    @classmethod
    def _features(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not _FEATURE_RE.match(value):
                raise ValueError(f"feature token must be UPPER.DOTTED: {value!r}")
        return values


class ExtensionEntrypoint(BaseModel):
    """Metadata about an entry point. Discovery never resolves ``target``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ExtensionEntrypointKind = ExtensionEntrypointKind.DECLARATIVE
    target: str = Field(default="", max_length=300)
    contract: str = Field(default="", max_length=64)

    @field_validator("target")
    @classmethod
    def _target(cls, value: str) -> str:
        if value and not _ENTRY_TARGET_RE.match(value):
            raise ValueError("target must be 'module:attribute'")
        return value


class ExtensionArtifact(BaseModel):
    """Artifact identity. Digests are carried, verification is optional."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_digest: str = Field(default="", max_length=128)
    manifest_digest: str = Field(default="", max_length=128)
    source_revision: str = Field(default="", max_length=120)
    signature_metadata: dict[str, str] = Field(default_factory=dict)
    attestation_metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("artifact_digest", "manifest_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if value and not _DIGEST_RE.match(value):
            raise ValueError("digest must be a sha256 hex string")
        return value


class ExtensionProvenance(BaseModel):
    """Provenance records where an artifact came from. It never grants trust."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    distribution_name: str = Field(default="", max_length=200)
    distribution_version: str = Field(default="", max_length=64)
    artifact_digest: str = Field(default="", max_length=128)
    source_url: str = Field(default="", max_length=500)
    source_revision: str = Field(default="", max_length=120)
    build_provenance: str = Field(default="", max_length=500)
    publisher_identity: str = Field(default="", max_length=120)
    released_at: str = Field(default="", max_length=40)
    license: str = Field(default="", max_length=80)
    dependency_provenance: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("artifact_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if value and not _DIGEST_RE.match(value):
            raise ValueError("artifact_digest must be a sha256 hex string")
        return value


class ExtensionSecurityProfile(BaseModel):
    """Declarative runtime needs. Declarations never become access.

    Values stay plain strings so the validator can classify a hostile
    declaration (``shell``, ``raw_credential_access``) with a specific
    forbidden-declaration code instead of a generic type error."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    declared_network: str = Field(default=NetworkRequirement.NONE.value, max_length=32)
    declared_filesystem: bool = False
    declared_process: str = Field(default=ProcessRequirement.NONE.value, max_length=64)
    declared_credentials: tuple[str, ...] = Field(default_factory=tuple)
    declared_data_access: tuple[str, ...] = Field(default_factory=tuple)
    runtime_requirements: tuple[str, ...] = Field(default_factory=tuple)


class ExtensionResource(BaseModel):
    """Package-scoped resource. Paths stay inside the package, always."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_id: str = Field(..., min_length=3, max_length=80)
    kind: ExtensionResourceKind = ExtensionResourceKind.STATIC_METADATA
    path: str = Field(..., min_length=1, max_length=512)
    media_type: str = Field(default="", max_length=80)
    digest: str = Field(default="", max_length=128)

    @field_validator("resource_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError("resource_id must be kebab-case")
        return value

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        from emo_cyber_agent.core.repository import RepositoryError

        try:
            return normalize_path(value)
        except RepositoryError as exc:
            raise ValueError(f"resource path denied: {exc}") from None

    @field_validator("digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if value and not _DIGEST_RE.match(value):
            raise ValueError("digest must be a sha256 hex string")
        return value


class ExtensionHealth(BaseModel):
    """Observed health, filled by the host. Never self-reported by content."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ExtensionHealthStatus = ExtensionHealthStatus.UNKNOWN
    checks: tuple[str, ...] = Field(default_factory=tuple)
    note: str = Field(default="", max_length=300)


class ExtensionTrust(BaseModel):
    """Trust evaluation result. Produced only by loader/catalog processes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state: ExtensionTrustState
    source_class: ExtensionSourceClass
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    evidence: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def resolvable(self) -> bool:
        return self.state.value in TRUSTED_STATES


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class ExtensionManifest(BaseModel):
    """The complete, frozen extension manifest.

    ``digest`` is the declared identity digest: the validator recomputes
    ``identity_digest`` from the canonical payload and refuses a mismatch,
    so a single edited field invalidates the whole declaration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    extension_id: str = Field(..., min_length=3, max_length=80)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(..., min_length=5, max_length=32)
    extension_type: ExtensionType
    description: str = Field(..., min_length=1, max_length=1000)
    api_version: str = Field(default=EXTENSION_API_VERSION, max_length=16)
    supported_emo_versions: tuple[str, ...] = Field(default_factory=tuple)
    dependencies: tuple[ExtensionDependency, ...] = Field(default_factory=tuple)
    optional_dependencies: tuple[ExtensionDependency, ...] = Field(default_factory=tuple)
    provides: ExtensionCapabilityDeclaration = Field(default_factory=ExtensionCapabilityDeclaration)
    requires: tuple[str, ...] = Field(default_factory=tuple)
    entrypoint_metadata: ExtensionEntrypoint = Field(default_factory=ExtensionEntrypoint)
    artifact_identity: ExtensionArtifact = Field(default_factory=ExtensionArtifact)
    source_provenance: ExtensionProvenance = Field(default_factory=ExtensionProvenance)
    license: str = Field(..., min_length=1, max_length=80)
    security_metadata: ExtensionSecurityProfile = Field(default_factory=ExtensionSecurityProfile)
    compatibility: ExtensionCompatibility = Field(default_factory=ExtensionCompatibility)
    resources: tuple[ExtensionResource, ...] = Field(default_factory=tuple)
    dataset_classification: DatasetClassification = DatasetClassification.INTERNAL
    digest: str = Field(default="", max_length=128)

    @field_validator("extension_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError("extension_id must be kebab-case")
        return value

    @field_validator("version")
    @classmethod
    def _version(cls, value: str) -> str:
        parse_version(value)
        return value

    @field_validator("api_version")
    @classmethod
    def _api(cls, value: str) -> str:
        if not _API_RE.match(value):
            raise ValueError("api_version must look like X.Y")
        return value

    @field_validator("requires")
    @classmethod
    def _features(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not _FEATURE_RE.match(value):
                raise ValueError(f"feature token must be UPPER.DOTTED: {value!r}")
        return values

    @field_validator("supported_emo_versions")
    @classmethod
    def _supported(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if value.strip() == "*":
                continue
            for part in value.split(","):
                operator, operand = split_constraint(part)
                if operator not in (">=", "<=", "==", "!=", ">", "<", "~="):
                    raise ValueError(f"unsupported supported_emo_versions operator: {part!r}")
                if not re.match(r"^\d+(\.\d+){0,2}$", operand):
                    raise ValueError(f"unsupported supported_emo_versions operand: {operand!r}")
        return values

    @field_validator("digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if value and not _DIGEST_RE.match(value):
            raise ValueError("digest must be a sha256 hex string")
        return value

    @property
    def identity(self) -> ExtensionIdentity:
        return ExtensionIdentity(
            extension_id=self.extension_id,
            name=self.name,
            version=self.version,
            extension_type=self.extension_type,
        )

    @property
    def type_value(self) -> str:
        return self.extension_type.value

    @property
    def is_declarative(self) -> bool:
        return self.type_value in DECLARATIVE_TYPES

    @property
    def is_executable(self) -> bool:
        return self.type_value in EXECUTABLE_TYPES

    def identity_payload(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        for name in IDENTITY_EXCLUDED_FIELDS:
            data.pop(name, None)
        return data

    @property
    def identity_digest(self) -> str:
        return manifest_identity_digest(self.identity_payload())

    @property
    def declared_capabilities(self) -> tuple[str, ...]:
        return tuple(member.value for member in self.provides.declares)

    def textual_fields(self) -> tuple[str, ...]:
        """Every free-text field that can carry a hostile instruction.

        Used by the validator's identifier-aware authority scan."""
        fields: list[str] = [self.name, self.description, self.license]
        fields.extend(self.requires)
        fields.extend(self.provides.provides_feature)
        fields.extend(self.provides.optional_feature)
        fields.extend(dep.extension_id for dep in (*self.dependencies, *self.optional_dependencies))
        fields.append(self.entrypoint_metadata.target)
        fields.append(self.entrypoint_metadata.contract)
        fields.append(self.source_provenance.publisher_identity)
        fields.append(self.source_provenance.source_url)
        fields.append(self.source_provenance.build_provenance)
        fields.extend(self.source_provenance.dependency_provenance)
        fields.extend(res.resource_id for res in self.resources)
        fields.extend(self.security_metadata.declared_data_access)
        fields.extend(self.security_metadata.runtime_requirements)
        return tuple(fields)
