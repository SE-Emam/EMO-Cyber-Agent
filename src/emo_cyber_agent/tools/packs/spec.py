"""Tool pack domain — POST-RC-007.

A Tool Pack declares WHAT TOOL EXISTS + HOW IT IS INVOKED + WHAT
FACTS IT PRODUCES. It grants nothing, decides nothing, executes
nothing, confirms nothing. Execution stays on the existing path:
ToolRegistry → StrictPolicyEngine → ToolExecutor → adapter →
normalized result → Evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

TOOL_PACK_SPEC_VERSION = "1.0"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_VER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_BINARY_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,63}$")
_FLAG_RE = re.compile(r"^--[a-z][a-z0-9\-]*$")
_INPUT_NAME_RE = re.compile(r"^[a-z_]{1,40}$")
_VERSION_RANGE_RE = re.compile(r"^([<>]=?|==|~=)?\d+\.\d+\.\d+(\s*,\s*([<>]=?|==|~=)?\d+\.\d+\.\d+)*$")
_SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/=:,]*$")

# Closed capability taxonomy. Anything else is unknown; anything
# write-ish is escalation. No vendor-specific entries.
ALLOWED_PACK_CAPABILITIES: tuple[str, ...] = (
    "CODE_PATTERN_SCAN",
    "DEPENDENCY_SCAN",
    "VULNERABILITY_LOOKUP",
    "MISCONFIGURATION_SCAN",
    "SECRET_DETECTION",
    "SBOM_SCAN",
    "STATIC_ANALYSIS",
    "LOCAL_REPOSITORY_SCAN",
)

WRITE_CAPABILITY_FRAGMENTS: tuple[str, ...] = (
    "WRITE", "DELETE", "PATCH", "COMMIT", "PUSH", "MERGE", "DEPLOY",
    "FIX", "REMEDIATE", "EXECUTE_REMOTE", "ADMIN", "PRIVILEGE_ESCALATION",
    "write", "destructive", "admin", "delete", "exfiltrate", "grant",
)

# Shell-semantics markers: banned from every pack string field.
SHELL_MARKERS: tuple[str, ...] = (
    "shell=true", "shell_command", "arbitrary_command",
    "command_template_from_user", "extra_args", "raw_flags",
)

INPUT_TYPES: tuple[str, ...] = ("string", "integer", "boolean", "path", "ref", "enum", "snapshot_id")
BANNED_INPUT_NAMES: tuple[str, ...] = ("argv", "command", "shell", "flags", "raw", "raw_flags", "extra_args", "config", "script")


class PackTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"


class MaintenanceStatus(StrEnum):
    ACTIVE = "active"
    SECURITY_ONLY = "security_only"
    DEPRECATED = "deprecated"
    UNKNOWN = "unknown"


class NetworkRequirement(StrEnum):
    NONE = "network_none"
    REQUIRED = "network_required"
    OPTIONAL = "network_optional"


class ToolHealth(StrEnum):
    AVAILABLE = "available"
    MISSING = "missing"
    UNSUPPORTED = "unsupported"
    VERSION_UNSUPPORTED = "version_unsupported"
    BROKEN = "broken"
    POLICY_BLOCKED = "policy_blocked"
    NETWORK_UNAVAILABLE = "network_unavailable"


def is_escalation_capability(cap: str) -> bool:
    lowered = cap.lower()
    upper = cap.upper()
    return any(frag in cap or frag in lowered or frag in upper for frag in WRITE_CAPABILITY_FRAGMENTS)


def contains_shell_semantics(text: str) -> str | None:
    lowered = (text or "").lower()
    for marker in SHELL_MARKERS:
        if marker in lowered:
            return marker
    return None


class ToolCapability(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str = Field(...)
    description: str = Field(default="", max_length=300)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if v not in ALLOWED_PACK_CAPABILITIES:
            raise ValueError(f"capability not allowlisted: {v}")
        return v


class ToolInputField(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str = Field(...)
    type: str = Field(...)
    required: bool = False
    description: str = Field(default="", max_length=300)
    allowed_values: tuple[str, ...] = ()
    max_length: int = Field(default=512, ge=1, le=4096)
    min_value: int | None = None
    max_value: int | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not _INPUT_NAME_RE.match(v):
            raise ValueError(f"input name must be snake_case: {v}")
        if v in BANNED_INPUT_NAMES:
            raise ValueError(f"input name banned (passthrough risk): {v}")
        return v

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        if v not in INPUT_TYPES:
            raise ValueError(f"input type not allowlisted: {v}")
        return v


class ToolInputContract(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    fields: tuple[ToolInputField, ...] = ()


class ToolOutputContract(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    record_kinds: tuple[str, ...] = ()
    retains_raw: bool = False
    raw_limit: int = Field(default=4096, ge=0, le=65536)
    redaction: bool = True


class ToolRuntimeProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    entrypoint: str = Field(...)
    timeout_s: int = Field(default=120, ge=1, le=1800)
    stdout_limit: int = Field(default=65536, ge=1024, le=1048576)
    stderr_limit: int = Field(default=16384, ge=1024, le=262144)
    cwd_scoped: bool = True
    env_allowlist: tuple[str, ...] = ()

    @field_validator("entrypoint")
    @classmethod
    def _entrypoint(cls, v: str) -> str:
        if not _BINARY_RE.match(v):
            raise ValueError(f"entrypoint must be a bare binary name: {v}")
        if "/" in v or "\\" in v or v.startswith("-"):
            raise ValueError(f"entrypoint must not be a path or flag: {v}")
        return v


class ToolVersionInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    tool_id: str = Field(..., min_length=1, max_length=80)
    version: str = Field(..., min_length=1, max_length=40)
    adapter_version: str = Field(default="", max_length=40)


class ToolDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    definition_id: str = Field(...)
    tool_id: str = Field(..., min_length=1, max_length=80)
    tool_capability: str = Field(default="scanner.local.execute", min_length=1, max_length=80)
    mode: str = Field(..., min_length=1, max_length=40)
    version_range: str = Field(default=">=1.0.0", max_length=80)
    adapter: str = Field(..., min_length=1, max_length=80)
    capabilities: tuple[str, ...] = ()
    inputs: ToolInputContract = Field(default_factory=ToolInputContract)
    outputs: ToolOutputContract = Field(default_factory=ToolOutputContract)
    runtime: ToolRuntimeProfile = Field(...)
    network: NetworkRequirement = NetworkRequirement.NONE
    supported_targets: tuple[str, ...] = ("repo",)
    snapshot_binding: bool = False
    executable: bool = True
    fixed_args: tuple[str, ...] = ()
    value_flags: tuple[str, ...] = ()

    @field_validator("definition_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("definition_id must be kebab-case")
        return v

    @field_validator("version_range")
    @classmethod
    def _range(cls, v: str) -> str:
        if not _VERSION_RANGE_RE.match(v):
            raise ValueError(f"version_range must be a simple specifier: {v}")
        return v


class ToolPack(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pack_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(...)
    vendor: str = Field(default="", max_length=120)
    description: str = Field(..., min_length=1, max_length=1000)
    tool_version_range: str = Field(default=">=1.0.0", max_length=80)
    maintenance_status: MaintenanceStatus = MaintenanceStatus.ACTIVE
    license: str = Field(default="", max_length=120)
    source_provenance: str = Field(default="", max_length=300)
    entrypoint: str = Field(...)
    supported_platforms: tuple[str, ...] = ()
    supported_targets: tuple[str, ...] = ("repo",)
    definitions: tuple[ToolDefinition, ...] = ()
    network_default: NetworkRequirement = NetworkRequirement.NONE
    filesystem_read_only: bool = True
    resource_limits: dict[str, Any] = Field(default_factory=dict)
    secret_handling: str = Field(default="redact-and-never-persist", max_length=80)
    redaction_rules: tuple[str, ...] = ()
    evidence_mapping: dict[str, str] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("pack_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("pack_id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VER_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @field_validator("entrypoint")
    @classmethod
    def _entrypoint(cls, v: str) -> str:
        if not _BINARY_RE.match(v):
            raise ValueError(f"entrypoint must be a bare binary name: {v}")
        return v

    @staticmethod
    def digest_of(pack: ToolPack) -> str:
        canonical = json.dumps(pack.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


class ResolvedTool(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    pack_id: str
    pack_version: str
    definition_id: str
    tool_id: str
    capability: str = ""
    health: ToolHealth = ToolHealth.AVAILABLE
    degraded: bool = False
    reason: str = ""
    resolved_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ToolHealthReport(BaseModel):
    """Safe presence/version metadata only. Never secrets, tokens, env contents."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    tool_id: str
    status: ToolHealth = ToolHealth.MISSING
    installed_version: str = ""
    reason: str = ""
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class NormalizedToolResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    tool_id: str
    tool_version: str = ""
    invocation_id: str = ""
    audit_id: str = ""
    project_id: str = ""
    snapshot_id: str = ""
    observed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "completed"
    raw_digest: str = ""
    normalized_records: tuple[dict[str, Any], ...] = ()
    limitations: tuple[str, ...] = ()
    coverage: str = "complete"
    provenance: dict[str, Any] = Field(default_factory=dict)
