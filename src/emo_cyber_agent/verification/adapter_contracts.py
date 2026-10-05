"""Verification adapter contracts — POST-RC-012.

The explicit, frozen, provider-agnostic implementation boundary
that turns a VerificationPlan into bounded execution behind the
Core/ToolExecutor boundary. Contracts are data: they grant no
permission, own no authorization, and open no transport of their
own. Any response is UNTRUSTED PROVIDER DATA until Core interprets
observed facts through a typed oracle.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

ADAPTER_SCHEMA_VERSION = "1.0"

ADAPTER_CAPABILITIES: tuple[str, ...] = (
    "HTTP_REQUEST",
    "HTTP_ASSERTION",
    "AUTHZ_MATRIX",
    "CONFIG_ASSERTION",
    "FILE_ASSERTION",
    "DATABASE_ASSERTION",
    "PROCESS_ASSERTION",
    "GRAPH_ASSERTION",
    "STRUCTURED_TOOL_ASSERTION",
    "MCP_ASSERTION",
    "AGENT_BOUNDARY_ASSERTION",
    "SYNTHETIC_IDENTITY_TEST",
)

# Capability names that imply write/destructive/privilege expansion.
# Registering one is a hard escalation error, not a warning.
ESCALATION_CAPABILITY_TOKENS: tuple[str, ...] = (
    "write", "delete", "exec", "grant", "admin", "remediat", "deploy",
    "mutate", "transfer", "escalat", "privilege", "shell", "install",
)

FORBIDDEN_REQUEST_FIELDS: tuple[str, ...] = (
    "raw_command", "shell", "shell_command", "arbitrary_argv", "arbitrary_sql",
    "arbitrary_url", "arbitrary_code", "model_prompt", "permission_grant",
    "policy_override", "finding_state", "finding_severity",
)

FORBIDDEN_INPUT_KEYS: tuple[str, ...] = FORBIDDEN_REQUEST_FIELDS

# Words that would turn provider text into authority. They are never
# accepted as fields; in free text they only raise a data flag.
AUTHORITY_TOKENS: tuple[str, ...] = (
    "confirmed", "vulnerable", "critical", "fixed", "approve", "promote",
    "resolve", "grant", "safe", "severity",
)

_CODE_MARKERS: tuple[str, ...] = ("__import__", "eval(", "exec(", "compile(", "subprocess", "shell=True", "os.system", "0x")


class AdapterHealthState(StrEnum):
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    UNSUPPORTED = "UNSUPPORTED"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"
    BROKEN = "BROKEN"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    RESOURCE_LIMITED = "RESOURCE_LIMITED"


class AdapterExecutionStatus(StrEnum):
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    MALFORMED = "MALFORMED"


class OperationalResult(StrEnum):
    """Environment/operational outcomes. None of these is a security
    result: they can only ever map to INCONCLUSIVE or BLOCKED."""

    OK = "OK"
    TARGET_UNAVAILABLE = "TARGET_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    AUTH_UNAVAILABLE = "AUTH_UNAVAILABLE"
    NETWORK_DENIED = "NETWORK_DENIED"
    FIXTURE_MISSING = "FIXTURE_MISSING"
    TOOL_MISSING = "TOOL_MISSING"
    ENV_MISCONFIGURED = "ENV_MISCONFIGURED"
    RESOURCE_LIMITED = "RESOURCE_LIMITED"
    POLICY_DENIED = "POLICY_DENIED"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    TARGET_CHANGED = "TARGET_CHANGED"
    VERSION_MISMATCH = "VERSION_MISMATCH"


OPERATIONAL_ONLY: frozenset[str] = frozenset(
    state.value for state in OperationalResult if state is not OperationalResult.OK
)


def assert_no_code_markers(*texts: str) -> None:
    for text in texts:
        lowered = (text or "").lower()
        for marker in _CODE_MARKERS:
            if marker.lower() in lowered:
                raise ValueError(f"code-like adapter input denied: {marker}")


def flag_authority_language(*texts: str) -> tuple[str, ...]:
    """Provider text carrying authority words stays untrusted data.
    The flags never become a verification state."""
    import re as _re

    flags: list[str] = []
    for text in texts:
        lowered = (text or "").lower()
        for token in AUTHORITY_TOKENS:
            if _re.search(rf"(?<![\w.:/-]){_re.escape(token)}(?![\w-])", lowered) and token not in flags:
                flags.append(token)
    return tuple(sorted(flags))


class VerificationAdapterCapabilities(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    capabilities: tuple[str, ...] = ()
    supported_target_kinds: tuple[str, ...] = ()
    supported_strategy_ids: tuple[str, ...] = ()
    contract_version: str = Field(default=ADAPTER_SCHEMA_VERSION, max_length=40)

    @field_validator("capabilities")
    @classmethod
    def _known(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for capability in v:
            lowered = capability.lower()
            for token in ESCALATION_CAPABILITY_TOKENS:
                if token in lowered:
                    raise ValueError(f"capability implies escalation: {capability}")
            if capability not in ADAPTER_CAPABILITIES:
                raise ValueError(f"unknown adapter capability: {capability}")
        return tuple(dict.fromkeys(v))


class VerificationAdapterHealth(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    state: str = AdapterHealthState.AVAILABLE.value
    reason: str = Field(default="", max_length=300)
    provider_version: str = Field(default="", max_length=60)
    contract_version: str = Field(default=ADAPTER_SCHEMA_VERSION, max_length=40)

    @field_validator("state")
    @classmethod
    def _state(cls, v: str) -> str:
        if v not in tuple(state.value for state in AdapterHealthState):
            raise ValueError(f"health state not allowed: {v}")
        return v

    @property
    def available(self) -> bool:
        return self.state == AdapterHealthState.AVAILABLE.value


class VerificationAdapterContext(BaseModel):
    """Immutable execution context. The adapter rejects any mismatch
    instead of reinterpreting it."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    verification_id: str = Field(..., min_length=1, max_length=120)
    policy_version: str = Field(..., min_length=1, max_length=60)
    policy_decision_id: str = Field(..., min_length=1, max_length=120)
    strategy_id: str = Field(..., min_length=1, max_length=80)
    strategy_version: str = Field(..., min_length=1, max_length=40)
    adapter_id: str = Field(default="", max_length=80)
    adapter_version: str = Field(default="", max_length=40)
    target_identity: str = Field(..., min_length=1, max_length=400)


class VerificationAdapterRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    verification_id: str = Field(..., min_length=1, max_length=120)
    strategy_id: str = Field(..., min_length=1, max_length=80)
    strategy_version: str = Field(..., min_length=1, max_length=40)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    target_kind: str = Field(..., min_length=1, max_length=60)
    target_identity: str = Field(..., min_length=1, max_length=400)
    normalized_inputs: dict[str, Any] = Field(default_factory=dict)
    required_capabilities: tuple[str, ...] = ()
    safety_level: str = Field(..., min_length=1, max_length=40)
    budget: dict[str, int] = Field(default_factory=dict)
    oracle_contract: tuple[str, ...] = ()
    policy_decision_id: str = Field(..., min_length=1, max_length=120)
    correlation_context: dict[str, str] = Field(default_factory=dict)

    @field_validator("normalized_inputs", "correlation_context")
    @classmethod
    def _clean(cls, v: dict[str, Any]) -> dict[str, Any]:
        for key, value in v.items():
            lowered = str(key).lower()
            if lowered in FORBIDDEN_INPUT_KEYS:
                raise ValueError(f"forbidden adapter request field: {key}")
            for token in ESCALATION_CAPABILITY_TOKENS:
                if token in lowered:
                    raise ValueError(f"capability-like request key denied: {key}")
            if isinstance(value, str):
                assert_no_code_markers(value)
        return v

    @field_validator("target_identity")
    @classmethod
    def _target(cls, v: str) -> str:
        value = v.strip()
        if not value or value == "*" or value.lower() in ("all", "any", "external_url", "arbitrary_host", "arbitrary_command"):
            raise ValueError("wildcard/arbitrary target denied")
        if value.lower().startswith(("http://", "https://")):
            raise ValueError("external target denied")
        if ".." in value.replace("\\", "/").split("/"):
            raise ValueError("traversal in target denied")
        if "\x00" in value:
            raise ValueError("null byte denied")
        return value

    @field_validator("safety_level")
    @classmethod
    def _safety(cls, v: str) -> str:
        if v not in ("PASSIVE", "SAFE_ACTIVE", "RESTRICTED_ACTIVE"):
            raise ValueError(f"safety level not allowed: {v}")
        return v


class VerificationAdapterResponse(BaseModel):
    """Data only. No authority fields exist in the contract; authority
    language in free text only raises data flags."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    adapter_id: str = Field(..., min_length=1, max_length=80)
    adapter_version: str = Field(..., min_length=1, max_length=40)
    verification_id: str = Field(..., min_length=1, max_length=120)
    status: str
    observations: dict[str, Any] = Field(default_factory=dict)
    oracle_inputs: dict[str, Any] = Field(default_factory=dict)
    raw_digest: str = Field(default="", max_length=128)
    normalized_output: str = Field(default="", max_length=2000)
    coverage: str = Field(default="complete", max_length=24)
    limitations: tuple[str, ...] = ()
    operational_result: str = OperationalResult.OK.value
    provenance: dict[str, Any] = Field(default_factory=dict)
    data_flags: tuple[str, ...] = ()

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in tuple(status.value for status in AdapterExecutionStatus):
            raise ValueError(f"adapter status not allowed: {v}")
        return v

    @field_validator("operational_result")
    @classmethod
    def _operational(cls, v: str) -> str:
        if v not in tuple(result.value for result in OperationalResult):
            raise ValueError(f"operational result not allowed: {v}")
        return v

    def model_post_init(self, __context: Any, /) -> None:
        if not self.data_flags:
            derived = flag_authority_language(self.normalized_output, *[str(v) for v in self.observations.values()])
            if derived:
                object.__setattr__(self, "data_flags", derived)


class VerificationAdapter(ABC):
    """Provider implementation boundary. `execute` is not a general
    capability: it only ever runs inside a validated, policy-bound,
    budget-bounded adapter request that this contract cannot widen."""

    @property
    @abstractmethod
    def id(self) -> str: ...

    @property
    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def capabilities(self) -> VerificationAdapterCapabilities: ...

    @abstractmethod
    def health(self) -> VerificationAdapterHealth: ...

    @abstractmethod
    def validate(self, request: VerificationAdapterRequest) -> None: ...

    @abstractmethod
    def execute(self, request: VerificationAdapterRequest) -> VerificationAdapterResponse: ...

    @property
    @abstractmethod
    def provenance(self) -> dict[str, Any]: ...
