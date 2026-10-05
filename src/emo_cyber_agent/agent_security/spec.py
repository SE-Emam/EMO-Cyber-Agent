"""Agent security domain — POST-RC-010.

First-class security surface for AI/agent/MCP architectures:
system model, identity, delegation, capability graph, MCP
topology, attack surface, threat taxonomy, analyses, scenarios,
controls, handoffs. Frozen, typed, extra-forbidden,
audit/project/snapshot-bound, deterministic digests.

Nothing here hosts, calls, or selects models. Nothing grants,
approves, confirms, executes, or remediates. Threat scenarios
stay at or below SUPPORTED_BY_EVIDENCE, hypotheses stay
hypotheses, and every untrusted text stays data.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from emo_cyber_agent.threat_modeling.spec import canonical_digest

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_VER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_MATERIAL_REF_RE = re.compile(r"^(digest:[0-9a-f]{16,128}|ref:[a-z0-9\-/:.]{1,120})$")

# Whole-word authority verbs that must never appear in threat /
# security record prose. "approval" (control context) stays legal:
# the boundary stops at the verb forms.
_AUTHORITY_TOKENS: tuple[str, ...] = (
    "grant", "grants", "approve", "approves", "confirm", "confirms",
    "confirmed", "execute", "executes", "escalate_privilege", "autofix",
)

AGENT_ROLES: tuple[str, ...] = (
    "planner", "executor", "reviewer", "router", "tool-user",
    "supervisor", "worker", "unknown",
)

IDENTITY_KINDS: tuple[str, ...] = (
    "acts-as-user", "acts-for-user", "service-identity",
    "delegated-subset", "unknown",
)

CAPABILITY_KINDS: tuple[str, ...] = (
    "DECLARED_CAPABILITY", "OBSERVED_CAPABILITY",
    "EFFECTIVE_CAPABILITY", "UNKNOWN_CAPABILITY",
)

MCP_RELATIONS: tuple[str, ...] = (
    "TRUSTS", "DELEGATES_TO", "CALLS", "EXPOSES", "READS", "WRITES",
    "RETURNS_DATA_TO", "SUPPLIES_CONTEXT_TO", "DESCRIBES",
    "AUTHENTICATES_AS",
)

AGENT_SURFACE_CATEGORIES: tuple[str, ...] = (
    "MODEL_INPUT", "MODEL_OUTPUT", "SYSTEM_PROMPT", "DEVELOPER_INSTRUCTION",
    "USER_INPUT", "EXTERNAL_DOCUMENT", "REPOSITORY_CONTENT", "MEMORY",
    "RAG_RETRIEVAL", "SKILL", "TOOL", "MCP_TOOL", "MCP_RESOURCE",
    "MCP_PROMPT", "SUBAGENT", "DELEGATION", "CREDENTIAL", "IDENTITY",
    "CALLBACK", "WEBHOOK", "EXTERNAL_ENDPOINT",
)

AGENT_THREAT_CATEGORIES: tuple[str, ...] = (
    "GOAL_HIJACKING", "PROMPT_INJECTION", "INDIRECT_PROMPT_INJECTION",
    "TOOL_MISUSE", "TOOL_POISONING", "CONTEXT_SPOOFING", "DATA_POISONING",
    "IDENTITY_ABUSE", "PRIVILEGE_ABUSE", "SCOPE_CREEP", "CREDENTIAL_EXPOSURE",
    "SECRET_EXPOSURE", "SENSITIVE_DATA_EXFILTRATION", "UNTRUSTED_MEMORY",
    "MEMORY_POISONING", "INSECURE_DELEGATION", "SUBAGENT_CONFUSION",
    "EXCESSIVE_AGENCY", "UNBOUNDED_AUTONOMY", "OUTPUT_INJECTION",
    "SUPPLY_CHAIN", "MCP_AUTHORIZATION", "MCP_SERVER_TRUST",
    "MCP_RESOURCE_TRUST", "MCP_PROMPT_TRUST",
)

AGENT_HYPOTHESIS_STATUS: tuple[str, ...] = (
    "UNASSESSED", "HYPOTHESIZED", "SUPPORTED_BY_EVIDENCE",
    "REFUTED", "INCONCLUSIVE",
)

AGENT_CONTROL_KINDS: tuple[str, ...] = (
    "HUMAN_APPROVAL", "TOOL_ALLOWLIST", "CAPABILITY_SCOPING",
    "OUTPUT_VALIDATION", "INPUT_SANITIZATION", "CONTEXT_ISOLATION",
    "MEMORY_ISOLATION", "CREDENTIAL_SCOPING", "TOKEN_EXPIRATION",
    "AUDIT_LOGGING", "TOOL_RESULT_SANDBOXING", "MCP_SERVER_ALLOWLIST",
    "SERVER_IDENTITY_VERIFICATION", "RESOURCE_ISOLATION",
    "DELEGATION_LIMITS", "RATE_LIMITING",
)

AGENT_CONTROL_STATUS: tuple[str, ...] = (
    "OBSERVED_CONTROL", "DECLARED_CONTROL", "UNVERIFIED_CONTROL",
)

MCP_CHECK_KINDS: tuple[str, ...] = (
    "TOKEN_SCOPE_TOO_BROAD", "TOKEN_LIFETIME_TOO_LONG",
    "SERVER_IDENTITY_UNVERIFIED", "TOOL_IDENTITY_UNVERIFIED",
    "TOOL_DESCRIPTION_UNTRUSTED", "TOOL_OUTPUT_UNTRUSTED",
    "CREDENTIAL_IN_CONTEXT", "CREDENTIAL_IN_LOG_PATH",
    "SCOPE_WIDENING", "UNSCOPED_DELEGATION",
    "CROSS_BOUNDARY_DATA_FLOW",
    "UNTRUSTED_RESOURCE_TO_PRIVILEGED_TOOL",
    "UNTRUSTED_PROMPT_TO_PRIVILEGED_ACTION",
)

SURFACE_COMPLETENESS: tuple[str, ...] = (
    "NONE_OBSERVED", "FULLY_MAPPED", "PARTIALLY_MAPPED",
    "NOT_ANALYZED", "UNKNOWN",
)


class PackTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"


def assert_no_authority_language(*texts: str) -> None:
    from emo_cyber_agent.agent_security.errors import AgentSecurityError, AgentSecurityErrorCode

    for text in texts:
        lowered = (text or "").lower()
        for token in _AUTHORITY_TOKENS:
            # Standalone verb forms only: dotted capability names such as
            # code.execute or supabase.grant.read are data, not instructions.
            if re.search(rf"(?<![\w.:/-]){re.escape(token)}(?![\w-])", lowered):
                raise AgentSecurityError(AgentSecurityErrorCode.AUTHORITY_LANGUAGE, f"authority language denied: {token}")


def _kebab(value: str, field: str) -> str:
    if not _ID_RE.match(value):
        raise ValueError(f"{field} must be kebab-case")
    return value


class AgentIdentity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity_id: str = Field(...)
    kind: str = Field(...)
    principal: str = Field(default="", max_length=200)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("identity_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "identity_id")

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in IDENTITY_KINDS:
            raise ValueError(f"identity kind not allowed: {v}")
        return v


class AgentRole(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    role: str = Field(...)

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        if v not in AGENT_ROLES:
            raise ValueError(f"agent role not allowed: {v}")
        return v


class Agent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    agent_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=160)
    role: str = Field(default="unknown", max_length=40)
    identity_id: str = Field(default="", max_length=320)
    model_endpoint_id: str = Field(default="", max_length=320)
    skill_ids: tuple[str, ...] = ()
    tool_ids: tuple[str, ...] = ()
    subagent_ids: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("agent_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "agent_id")

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        if v not in AGENT_ROLES:
            raise ValueError(f"agent role not allowed: {v}")
        return v


class SubAgent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    subagent_id: str = Field(...)
    parent_id: str = Field(..., min_length=1, max_length=320)
    role: str = Field(default="worker", max_length=40)
    identity_id: str = Field(default="", max_length=320)
    skill_ids: tuple[str, ...] = ()
    tool_ids: tuple[str, ...] = ()
    delegation_id: str = Field(default="", max_length=320)

    @field_validator("subagent_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "subagent_id")


class Delegation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    delegation_id: str = Field(...)
    issuer: str = Field(..., min_length=1, max_length=320)
    subject: str = Field(..., min_length=1, max_length=320)
    delegate: str = Field(..., min_length=1, max_length=320)
    scope: tuple[str, ...] = ()
    audience: str = Field(default="", max_length=320)
    validity: str = Field(default="", max_length=120)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("delegation_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "delegation_id")


class ModelEndpoint(BaseModel):
    """Abstract model facts only. No provider classes exist in EMO."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    endpoint_id: str = Field(...)
    provider_identity: str = Field(default="unknown", max_length=160)
    model_identity: str = Field(default="unknown", max_length=160)
    version: str = Field(default="unknown", max_length=60)
    hosting_boundary: str = Field(default="unknown", max_length=160)
    input_data_policy: str = Field(default="unknown", max_length=200)
    output_data_policy: str = Field(default="unknown", max_length=200)
    retention_claim: str = Field(default="unknown", max_length=200)
    tool_use: str = Field(default="unknown", max_length=60)
    structured_output: str = Field(default="unknown", max_length=60)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("endpoint_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "endpoint_id")


class PromptSource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source_id: str = Field(...)
    kind: str = Field(..., min_length=1, max_length=60)
    trust: str = Field(default="untrusted", max_length=24)
    digest: str = Field(default="", max_length=128)

    @field_validator("source_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "source_id")


class ContextSource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source_id: str = Field(...)
    kind: str = Field(..., min_length=1, max_length=60)
    trust: str = Field(default="untrusted", max_length=24)
    digest: str = Field(default="", max_length=128)

    @field_validator("source_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "source_id")


class SkillBinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    agent_id: str = Field(..., min_length=1, max_length=320)
    skill_id: str = Field(..., min_length=1, max_length=120)
    provenance: dict[str, Any] = Field(default_factory=dict)


class ToolBinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    agent_id: str = Field(..., min_length=1, max_length=320)
    tool_id: str = Field(..., min_length=1, max_length=120)
    via_skill_id: str = Field(default="", max_length=120)
    provenance: dict[str, Any] = Field(default_factory=dict)


class MCPServer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    server_id: str = Field(...)
    identity: str = Field(default="unknown", max_length=200)
    origin: str = Field(default="unknown", max_length=320)
    transport: str = Field(default="unknown", max_length=60)
    protocol_version: str = Field(default="unknown", max_length=40)
    authorization_context: str = Field(default="unknown", max_length=200)
    capabilities: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("server_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "server_id")


class MCPClient(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    client_id: str = Field(...)
    agent_id: str = Field(default="", max_length=320)
    server_id: str = Field(default="", max_length=320)
    binding: str = Field(default="unknown", max_length=200)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("client_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "client_id")


class MCPTool(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    tool_id: str = Field(...)
    server_id: str = Field(default="", max_length=320)
    identity: str = Field(default="unknown", max_length=200)
    description_digest: str = Field(default="", max_length=128)
    schema_digest: str = Field(default="", max_length=128)
    version: str = Field(default="unknown", max_length=60)
    capabilities: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "tool_id")


class MCPResource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    resource_id: str = Field(...)
    server_id: str = Field(default="", max_length=320)
    identity: str = Field(default="unknown", max_length=320)
    trust: str = Field(default="untrusted", max_length=24)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("resource_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "resource_id")


class MCPPrompt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    prompt_id: str = Field(...)
    server_id: str = Field(default="", max_length=320)
    identity: str = Field(default="unknown", max_length=320)
    trust: str = Field(default="untrusted", max_length=24)
    digest: str = Field(default="", max_length=128)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("prompt_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "prompt_id")


class AgentSession(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    session_id: str = Field(...)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(default="", max_length=200)
    snapshot_id: str = Field(default="", max_length=160)
    agent_id: str = Field(..., min_length=1, max_length=320)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("session_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "session_id")


class TrustBoundary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    boundary_id: str = Field(...)
    kind: str = Field(..., min_length=1, max_length=60)
    basis: str = Field(default="UNKNOWN", max_length=24)
    provenance: dict[str, Any] = Field(default_factory=dict)
    protects: tuple[str, ...] = ()

    @field_validator("boundary_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "boundary_id")


class CapabilityBoundary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    boundary_id: str = Field(...)
    declared: tuple[str, ...] = ()
    effective: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("boundary_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "boundary_id")


class CredentialBoundary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    boundary_id: str = Field(...)
    sources: tuple[str, ...] = ()
    consumers: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("boundary_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "boundary_id")


class AgentDataFlow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    flow_id: str = Field(...)
    source: str = Field(..., min_length=1, max_length=320)
    target: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(default="data", max_length=60)
    crosses: tuple[str, ...] = ()

    @field_validator("flow_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "flow_id")


class AgentAction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    action_id: str = Field(...)
    actor_id: str = Field(..., min_length=1, max_length=320)
    action: str = Field(..., min_length=1, max_length=120)
    target: str = Field(default="", max_length=320)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "action_id")


class MemoryEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    entry_id: str = Field(...)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(default="", max_length=200)
    snapshot_id: str = Field(default="", max_length=160)
    digest: str = Field(default="", max_length=128)
    trust: str = Field(default="untrusted", max_length=24)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("entry_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "entry_id")


class RetrievalSource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source_id: str = Field(...)
    kind: str = Field(default="rag", max_length=60)
    trust: str = Field(default="untrusted", max_length=24)
    digest: str = Field(default="", max_length=128)

    @field_validator("source_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "source_id")


class CredentialSource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source_id: str = Field(...)
    kind: str = Field(default="secret", max_length=60)
    material_ref: str = Field(default="", max_length=160)

    @field_validator("source_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "source_id")

    @field_validator("material_ref")
    @classmethod
    def _material_ref(cls, v: str) -> str:
        if v and not _MATERIAL_REF_RE.match(v):
            raise ValueError("credential material must be a digest or locator reference, never raw material")
        return v


class CredentialConsumer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    consumer_id: str = Field(...)
    kind: str = Field(default="tool", max_length=60)

    @field_validator("consumer_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "consumer_id")


class CredentialFlow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    flow_id: str = Field(...)
    source_id: str = Field(..., min_length=1, max_length=320)
    consumer_id: str = Field(..., min_length=1, max_length=320)
    boundary_id: str = Field(default="", max_length=320)
    redacted: bool = True

    @field_validator("flow_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "flow_id")


class ToolResultParts(BaseModel):
    """One tool result split into isolated trust surfaces."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    result_id: str = Field(...)
    data_digest: str = Field(default="", max_length=128)
    instruction_like_digest: str = Field(default="", max_length=128)
    metadata_digest: str = Field(default="", max_length=128)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("result_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "result_id")


class AgentSystem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(default="", max_length=200)
    snapshot_id: str = Field(default="", max_length=160)
    agents: tuple[Agent, ...] = ()
    subagents: tuple[SubAgent, ...] = ()
    identities: tuple[AgentIdentity, ...] = ()
    delegations: tuple[Delegation, ...] = ()
    endpoints: tuple[ModelEndpoint, ...] = ()
    prompt_sources: tuple[PromptSource, ...] = ()
    context_sources: tuple[ContextSource, ...] = ()
    skill_bindings: tuple[SkillBinding, ...] = ()
    tool_bindings: tuple[ToolBinding, ...] = ()
    mcp_clients: tuple[MCPClient, ...] = ()
    mcp_servers: tuple[MCPServer, ...] = ()
    mcp_tools: tuple[MCPTool, ...] = ()
    mcp_resources: tuple[MCPResource, ...] = ()
    mcp_prompts: tuple[MCPPrompt, ...] = ()
    sessions: tuple[AgentSession, ...] = ()
    boundaries: tuple[TrustBoundary, ...] = ()
    capability_boundaries: tuple[CapabilityBoundary, ...] = ()
    credential_boundaries: tuple[CredentialBoundary, ...] = ()
    flows: tuple[AgentDataFlow, ...] = ()
    memories: tuple[MemoryEntry, ...] = ()
    retrieval_sources: tuple[RetrievalSource, ...] = ()
    credential_sources: tuple[CredentialSource, ...] = ()
    credential_flows: tuple[CredentialFlow, ...] = ()
    coverage: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()


class AgentAttackSurfaceElement(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    element_id: str = Field(...)
    category: str = Field(...)
    agent_id: str = Field(default="", max_length=320)
    component_id: str = Field(default="", max_length=320)
    evidence_ids: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)
    coverage: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()

    @field_validator("element_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "element_id")

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        if v not in AGENT_SURFACE_CATEGORIES:
            raise ValueError(f"agent surface category not allowed: {v}")
        return v


class AgentAttackSurfaceRelation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    from_id: str = Field(..., min_length=1, max_length=320)
    to_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(default="reaches", max_length=60)

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in MCP_RELATIONS:
            raise ValueError(f"relation kind not allowed: {v}")
        return v


class AgentAttackSurface(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(default="", max_length=200)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    elements: tuple[AgentAttackSurfaceElement, ...] = ()
    relations: tuple[AgentAttackSurfaceRelation, ...] = ()
    completeness: str = Field(default="UNKNOWN", max_length=24)
    coverage: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()


class AgentThreatScenario(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    scenario_id: str = Field(...)
    category: str = Field(...)
    actor: str = Field(default="", max_length=320)
    source: str = Field(default="", max_length=320)
    target: str = Field(default="", max_length=320)
    trust_boundaries: tuple[str, ...] = ()
    affected_agents: tuple[str, ...] = ()
    affected_tools: tuple[str, ...] = ()
    affected_assets: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    attack_sequence: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    control_ids: tuple[str, ...] = ()
    hypothesis_status: str = Field(default="HYPOTHESIZED", max_length=24)
    verification_requirements: tuple[str, ...] = ()
    coverage: str = Field(default="UNKNOWN", max_length=24)
    limitations: tuple[str, ...] = ()
    framework_mappings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scenario_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "scenario_id")

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        if v not in AGENT_THREAT_CATEGORIES:
            raise ValueError(f"agent threat category not allowed: {v}")
        return v

    @field_validator("hypothesis_status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in AGENT_HYPOTHESIS_STATUS:
            raise ValueError(f"hypothesis status not allowed: {v}")
        return v

    @model_validator(mode="after")
    def _no_authority_prose(self) -> AgentThreatScenario:
        assert_no_authority_language(*self.preconditions, *self.attack_sequence)
        return self


class AgentSecurityControl(BaseModel):
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
        return _kebab(v, "control_id")

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in AGENT_CONTROL_KINDS:
            raise ValueError(f"agent control kind not allowed: {v}")
        return v

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in AGENT_CONTROL_STATUS:
            raise ValueError(f"agent control status not allowed: {v}")
        return v


class AgentSecurityObservation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    observation_id: str = Field(...)
    kind: str = Field(..., min_length=1, max_length=80)
    statement: str = Field(..., min_length=1, max_length=1000)
    evidence_ids: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observation_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "observation_id")

    @field_validator("evidence_ids")
    @classmethod
    def _evidence_required(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("observation requires at least one evidence id")
        return v

    @model_validator(mode="after")
    def _no_authority_prose(self) -> AgentSecurityObservation:
        assert_no_authority_language(self.statement)
        return self


class AgentVerificationHandoff(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    handoff_id: str = Field(...)
    threat_scenario_id: str = Field(..., min_length=1, max_length=320)
    target_snapshot_id: str = Field(..., min_length=1, max_length=160)
    target_component: str = Field(default="", max_length=320)
    required_evidence: tuple[str, ...] = ()
    verification_method: str = Field(default="static_confirmation", max_length=60)
    safety_level: str = Field(default="passive", max_length=24)
    success_criteria: str = Field(default="", max_length=500)
    refutation_criteria: str = Field(default="", max_length=500)
    compatible_snapshots: tuple[str, ...] = ()

    @field_validator("handoff_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "handoff_id")

    @model_validator(mode="after")
    def _no_authority_prose(self) -> AgentVerificationHandoff:
        assert_no_authority_language(self.success_criteria, self.refutation_criteria)
        return self


class AgentThreatDelta(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    base_snapshot_id: str = Field(..., min_length=1, max_length=160)
    target_snapshot_id: str = Field(..., min_length=1, max_length=160)
    entries: tuple[dict[str, Any], ...] = ()
    limitations: tuple[str, ...] = ()


class AgentTemplateConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    template_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(...)
    scope: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    declared_servers: tuple[dict[str, Any], ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("template_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _kebab(v, "template_id")

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VER_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @staticmethod
    def digest_of(template: AgentTemplateConfig) -> str:

        return canonical_digest(template.model_dump(mode="json"))
