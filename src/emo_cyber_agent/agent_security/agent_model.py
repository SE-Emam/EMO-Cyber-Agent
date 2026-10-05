"""Agent system model builder — POST-RC-010.

Describes the declared agent architecture (agents, model
endpoints, context, skills, tools, MCP topology, sessions,
memories, credentials) as frozen facts. Local configuration is
never trusted: identities default to unknown, trust defaults to
untrusted, and every record carries provenance.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.agent_security.errors import AgentSecurityError, AgentSecurityErrorCode
from emo_cyber_agent.agent_security.spec import (
    Agent,
    AgentIdentity,
    AgentSession,
    AgentSystem,
    ContextSource,
    CredentialBoundary,
    CredentialFlow,
    CredentialSource,
    Delegation,
    MCPClient,
    MCPPrompt,
    MCPResource,
    MCPServer,
    MCPTool,
    MemoryEntry,
    ModelEndpoint,
    PromptSource,
    RetrievalSource,
    SkillBinding,
    SubAgent,
    ToolBinding,
)


def _slug(text: str) -> str:
    import re as _re

    slug = _re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug[:80] or "unnamed"


def build_agent_system(
    *,
    audit_id: str,
    project_id: str = "",
    snapshot_id: str = "",
    agents: tuple[dict[str, Any], ...] = (),
    subagents: tuple[dict[str, Any], ...] = (),
    identities: tuple[dict[str, Any], ...] = (),
    delegations: tuple[dict[str, Any], ...] = (),
    endpoints: tuple[dict[str, Any], ...] = (),
    prompt_sources: tuple[dict[str, Any], ...] = (),
    context_sources: tuple[dict[str, Any], ...] = (),
    skill_bindings: tuple[dict[str, Any], ...] = (),
    tool_bindings: tuple[dict[str, Any], ...] = (),
    mcp_clients: tuple[dict[str, Any], ...] = (),
    mcp_servers: tuple[dict[str, Any], ...] = (),
    mcp_tools: tuple[dict[str, Any], ...] = (),
    mcp_resources: tuple[dict[str, Any], ...] = (),
    mcp_prompts: tuple[dict[str, Any], ...] = (),
    sessions: tuple[dict[str, Any], ...] = (),
    memories: tuple[dict[str, Any], ...] = (),
    retrieval_sources: tuple[dict[str, Any], ...] = (),
    credential_sources: tuple[dict[str, Any], ...] = (),
    credential_flows: tuple[dict[str, Any], ...] = (),
) -> AgentSystem:
    if not audit_id:
        raise AgentSecurityError(AgentSecurityErrorCode.INVALID, "audit_id required")
    limitations: list[str] = []
    parsed_agents = [_agent(a) for a in agents]
    parsed_subagents = [_subagent(s) for s in subagents]
    parsed_identities = [_identity(i) for i in identities]
    parsed_delegations = [_delegation(d) for d in delegations]
    parsed_prompts = [_prompt_source(p) for p in prompt_sources]
    parsed_context = [_context_source(c) for c in context_sources]
    if not endpoints:
        limitations.append("no model endpoint declared: model facts unknown")
    if not sessions:
        limitations.append("no sessions recorded: session scoping unverified")
    credential_boundaries = _credential_boundaries(credential_sources, credential_flows)
    return AgentSystem(
        audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id,
        agents=tuple(parsed_agents), subagents=tuple(parsed_subagents),
        identities=tuple(parsed_identities), delegations=tuple(parsed_delegations),
        endpoints=tuple(_endpoint(e) for e in endpoints),
        prompt_sources=tuple(parsed_prompts), context_sources=tuple(parsed_context),
        skill_bindings=tuple(_skill_binding(s) for s in skill_bindings),
        tool_bindings=tuple(_tool_binding(t) for t in tool_bindings),
        mcp_clients=tuple(_mcp_client(c) for c in mcp_clients),
        mcp_servers=tuple(_mcp_server(s) for s in mcp_servers),
        mcp_tools=tuple(_mcp_tool(t) for t in mcp_tools),
        mcp_resources=tuple(_mcp_resource(r) for r in mcp_resources),
        mcp_prompts=tuple(_mcp_prompt(p) for p in mcp_prompts),
        sessions=tuple(_session(s, audit_id, project_id, snapshot_id) for s in sessions),
        boundaries=(),
        capability_boundaries=(), credential_boundaries=tuple(credential_boundaries),
        flows=(), memories=tuple(_memory(m, audit_id, project_id, snapshot_id) for m in memories),
        retrieval_sources=tuple(_retrieval(r) for r in retrieval_sources),
        credential_sources=tuple(_credential_source(c) for c in credential_sources),
        credential_flows=tuple(_credential_flow(f) for f in credential_flows),
        coverage="PARTIALLY_MAPPED" if limitations else "FULLY_MAPPED",
        limitations=tuple(limitations),
    )


def _agent(raw: dict[str, Any]) -> Agent:
    return Agent(
        agent_id=_slug(str(raw.get("id", "agent"))), name=str(raw.get("name", "agent"))[:160],
        role=str(raw.get("role", "unknown")), identity_id=str(raw.get("identity_id", ""))[:320],
        model_endpoint_id=str(raw.get("model_endpoint_id", ""))[:320],
        skill_ids=tuple(str(s)[:120] for s in raw.get("skill_ids", [])),
        tool_ids=tuple(str(t)[:120] for t in raw.get("tool_ids", [])),
        subagent_ids=tuple(str(s)[:320] for s in raw.get("subagent_ids", [])),
        provenance={"declared": True},
    )


def _subagent(raw: dict[str, Any]) -> SubAgent:
    return SubAgent(
        subagent_id=_slug(str(raw.get("id", "subagent"))), parent_id=str(raw.get("parent_id", ""))[:320],
        role=str(raw.get("role", "worker")), identity_id=str(raw.get("identity_id", ""))[:320],
        skill_ids=tuple(str(s)[:120] for s in raw.get("skill_ids", [])),
        tool_ids=tuple(str(t)[:120] for t in raw.get("tool_ids", [])),
        delegation_id=str(raw.get("delegation_id", ""))[:320],
    )


def _identity(raw: dict[str, Any]) -> AgentIdentity:
    return AgentIdentity(
        identity_id=_slug(str(raw.get("id", "identity"))), kind=str(raw.get("kind", "unknown")),
        principal=str(raw.get("principal", ""))[:200], provenance={"declared": True},
    )


def _delegation(raw: dict[str, Any]) -> Delegation:
    return Delegation(
        delegation_id=_slug(str(raw.get("id", "delegation"))), issuer=str(raw.get("issuer", ""))[:320],
        subject=str(raw.get("subject", ""))[:320], delegate=str(raw.get("delegate", ""))[:320],
        scope=tuple(str(s)[:120] for s in raw.get("scope", [])), audience=str(raw.get("audience", ""))[:320],
        validity=str(raw.get("validity", ""))[:120], provenance={"declared": True},
    )


def _endpoint(raw: dict[str, Any]) -> ModelEndpoint:
    return ModelEndpoint(
        endpoint_id=_slug(str(raw.get("id", "model"))),
        provider_identity=str(raw.get("provider_identity", "unknown"))[:160],
        model_identity=str(raw.get("model_identity", "unknown"))[:160],
        version=str(raw.get("version", "unknown"))[:60],
        hosting_boundary=str(raw.get("hosting_boundary", "unknown"))[:160],
        input_data_policy=str(raw.get("input_data_policy", "unknown"))[:200],
        output_data_policy=str(raw.get("output_data_policy", "unknown"))[:200],
        retention_claim=str(raw.get("retention_claim", "unknown"))[:200],
        tool_use=str(raw.get("tool_use", "unknown"))[:60],
        structured_output=str(raw.get("structured_output", "unknown"))[:60],
        provenance={"declared": True},
    )


def _prompt_source(raw: dict[str, Any]) -> PromptSource:
    return PromptSource(
        source_id=_slug(str(raw.get("id", "prompt"))), kind=str(raw.get("kind", "prompt"))[:60],
        trust="untrusted", digest=str(raw.get("digest", ""))[:128],
    )


def _context_source(raw: dict[str, Any]) -> ContextSource:
    return ContextSource(
        source_id=_slug(str(raw.get("id", "context"))), kind=str(raw.get("kind", "context"))[:60],
        trust="untrusted", digest=str(raw.get("digest", ""))[:128],
    )


def _skill_binding(raw: dict[str, Any]) -> SkillBinding:
    return SkillBinding(agent_id=str(raw.get("agent_id", ""))[:320], skill_id=str(raw.get("skill_id", ""))[:120], provenance={"declared": True})


def _tool_binding(raw: dict[str, Any]) -> ToolBinding:
    return ToolBinding(agent_id=str(raw.get("agent_id", ""))[:320], tool_id=str(raw.get("tool_id", ""))[:120], via_skill_id=str(raw.get("via_skill_id", ""))[:120], provenance={"declared": True})


def _mcp_client(raw: dict[str, Any]) -> MCPClient:
    return MCPClient(
        client_id=_slug(str(raw.get("id", "client"))), agent_id=str(raw.get("agent_id", ""))[:320],
        server_id=str(raw.get("server_id", ""))[:320], binding=str(raw.get("binding", "unknown"))[:200],
        provenance={"declared": True},
    )


def _mcp_server(raw: dict[str, Any]) -> MCPServer:
    return MCPServer(
        server_id=_slug(str(raw.get("id", "server"))), identity=str(raw.get("identity", "unknown"))[:200],
        origin=str(raw.get("origin", "unknown"))[:320], transport=str(raw.get("transport", "unknown"))[:60],
        protocol_version=str(raw.get("protocol_version", "unknown"))[:40],
        authorization_context=str(raw.get("authorization_context", "unknown"))[:200],
        capabilities=tuple(str(c)[:80] for c in raw.get("capabilities", [])),
        provenance={"declared": True},
    )


def _mcp_tool(raw: dict[str, Any]) -> MCPTool:
    return MCPTool(
        tool_id=_slug(str(raw.get("id", "tool"))), server_id=str(raw.get("server_id", ""))[:320],
        identity=str(raw.get("identity", "unknown"))[:200],
        description_digest=str(raw.get("description_digest", ""))[:128],
        schema_digest=str(raw.get("schema_digest", ""))[:128],
        version=str(raw.get("version", "unknown"))[:60],
        capabilities=tuple(str(c)[:80] for c in raw.get("capabilities", [])),
        provenance={"declared": True},
    )


def _mcp_resource(raw: dict[str, Any]) -> MCPResource:
    return MCPResource(
        resource_id=_slug(str(raw.get("id", "resource"))), server_id=str(raw.get("server_id", ""))[:320],
        identity=str(raw.get("identity", "unknown"))[:320], trust="untrusted",
        provenance={"declared": True},
    )


def _mcp_prompt(raw: dict[str, Any]) -> MCPPrompt:
    return MCPPrompt(
        prompt_id=_slug(str(raw.get("id", "prompt"))), server_id=str(raw.get("server_id", ""))[:320],
        identity=str(raw.get("identity", "unknown"))[:320], trust="untrusted",
        digest=str(raw.get("digest", ""))[:128], provenance={"declared": True},
    )


def _session(raw: dict[str, Any], audit_id: str, project_id: str, snapshot_id: str) -> AgentSession:
    session_audit = str(raw.get("audit_id", audit_id))
    if session_audit != audit_id:
        raise AgentSecurityError(AgentSecurityErrorCode.CROSS_AUDIT, "session bound to a different audit")
    return AgentSession(
        session_id=_slug(str(raw.get("id", "session"))), audit_id=audit_id, project_id=project_id,
        snapshot_id=snapshot_id, agent_id=str(raw.get("agent_id", ""))[:320],
        provenance={"declared": True},
    )


def _memory(raw: dict[str, Any], audit_id: str, project_id: str, snapshot_id: str) -> MemoryEntry:
    return MemoryEntry(
        entry_id=_slug(str(raw.get("id", "memory"))), audit_id=audit_id, project_id=project_id,
        snapshot_id=snapshot_id, digest=str(raw.get("digest", ""))[:128],
        trust="untrusted", provenance={"declared": True},
    )


def _retrieval(raw: dict[str, Any]) -> RetrievalSource:
    return RetrievalSource(
        source_id=_slug(str(raw.get("id", "retrieval"))), kind=str(raw.get("kind", "rag"))[:60],
        trust="untrusted", digest=str(raw.get("digest", ""))[:128],
    )


def _credential_source(raw: dict[str, Any]) -> CredentialSource:
    return CredentialSource(
        source_id=_slug(str(raw.get("id", "credential"))), kind=str(raw.get("kind", "secret"))[:60],
        material_ref=str(raw.get("material_ref", ""))[:160],
    )


def _credential_flow(raw: dict[str, Any]) -> CredentialFlow:
    return CredentialFlow(
        flow_id=_slug(str(raw.get("id", "credential-flow"))), source_id=str(raw.get("source_id", ""))[:320],
        consumer_id=str(raw.get("consumer_id", ""))[:320], boundary_id=str(raw.get("boundary_id", ""))[:320],
        redacted=bool(raw.get("redacted", True)),
    )


def _credential_boundaries(sources: tuple[dict[str, Any], ...], flows: tuple[dict[str, Any], ...]) -> list[CredentialBoundary]:
    by_source: dict[str, list[str]] = {}
    for flow in flows:
        by_source.setdefault(str(flow.get("source_id", "")), []).append(str(flow.get("consumer_id", "")))
    return [CredentialBoundary(boundary_id=f"credential-boundary-{_slug(sid)}", sources=(sid,), consumers=tuple(sorted(set(consumers)))) for sid, consumers in sorted(by_source.items())]
