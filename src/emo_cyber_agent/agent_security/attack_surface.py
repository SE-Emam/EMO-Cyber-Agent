"""Agent attack surface builder — POST-RC-010.

Independent, queryable surface facts over agents, MCP topology,
context, memory, skills, tools, identity, delegation, and
credentials. A tool existing is never an exploitability claim.
Completeness is contractual: nothing analyzed means UNKNOWN,
never NONE.
"""

from __future__ import annotations


from emo_cyber_agent.agent_security.provenance import build_agent_provenance
from emo_cyber_agent.agent_security.spec import (
    AgentAttackSurface,
    AgentAttackSurfaceElement,
    AgentAttackSurfaceRelation,
    AgentSystem,
)


def _slug(text: str) -> str:
    import re as _re

    slug = _re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug[:80] or "unnamed"


def build_agent_attack_surface(
    system: AgentSystem,
    *,
    evidence_index: dict[str, tuple[str, ...]] | None = None,
) -> AgentAttackSurface:
    evidence_index = evidence_index or {}
    limitations: list[str] = list(system.limitations)
    elements: list[AgentAttackSurfaceElement] = []
    relations: list[AgentAttackSurfaceRelation] = []

    def _element(category: str, subject: str, agent_id: str = "", component: str = "") -> AgentAttackSurfaceElement:
        return AgentAttackSurfaceElement(
            element_id=f"agent-surface-{_slug(category)}-{_slug(subject)}", category=category,
            agent_id=agent_id, component_id=component,
            evidence_ids=tuple(evidence_index.get(subject, ())),
            provenance=build_agent_provenance(
                audit_id=system.audit_id, project_id=system.project_id, snapshot_id=system.snapshot_id,
                subject_id=subject, coverage=system.coverage,
            ),
            coverage=system.coverage, limitations=(),
        )

    for agent in sorted(system.agents, key=lambda a: a.agent_id):
        if agent.model_endpoint_id:
            elements.append(_element("MODEL_INPUT", agent.agent_id, agent_id=agent.agent_id))
            elements.append(_element("MODEL_OUTPUT", agent.agent_id, agent_id=agent.agent_id))
        for skill_id in sorted(set(agent.skill_ids)):
            elements.append(_element("SKILL", f"{agent.agent_id}-{skill_id}", agent_id=agent.agent_id, component=skill_id))
            relations.append(AgentAttackSurfaceRelation(from_id=agent.agent_id, to_id=f"agent-surface-skill-{_slug(agent.agent_id + '-' + skill_id)}", kind="CALLS"))
        for tool_id in sorted(set(agent.tool_ids)):
            elements.append(_element("TOOL", f"{agent.agent_id}-{tool_id}", agent_id=agent.agent_id, component=tool_id))
    for sub in sorted(system.subagents, key=lambda s: s.subagent_id):
        elements.append(_element("SUBAGENT", sub.subagent_id, agent_id=sub.parent_id))
        relations.append(AgentAttackSurfaceRelation(from_id=sub.parent_id, to_id=sub.subagent_id, kind="DELEGATES_TO"))
        for tool_id in sorted(set(sub.tool_ids)):
            elements.append(_element("TOOL", f"{sub.subagent_id}-{tool_id}", agent_id=sub.subagent_id, component=tool_id))
    for source in sorted(system.prompt_sources, key=lambda s: s.source_id):
        elements.append(_element("SYSTEM_PROMPT" if "system" in source.kind else "DEVELOPER_INSTRUCTION", source.source_id))
    for source in sorted(system.context_sources, key=lambda s: s.source_id):
        kind = {"user": "USER_INPUT", "document": "EXTERNAL_DOCUMENT", "repository": "REPOSITORY_CONTENT"}.get(source.kind, "EXTERNAL_DOCUMENT")
        elements.append(_element(kind, source.source_id))
    for memory in sorted(system.memories, key=lambda m: m.entry_id):
        elements.append(_element("MEMORY", memory.entry_id, agent_id=""))
    for retrieval in sorted(system.retrieval_sources, key=lambda r: r.source_id):
        elements.append(_element("RAG_RETRIEVAL", retrieval.source_id))
    for client in sorted(system.mcp_clients, key=lambda c: c.client_id):
        relations.append(AgentAttackSurfaceRelation(from_id=client.agent_id or client.client_id, to_id=client.server_id or "unknown-server", kind="CALLS"))
    for tool in sorted(system.mcp_tools, key=lambda t: t.tool_id):
        elements.append(_element("MCP_TOOL", tool.tool_id, component=tool.server_id))
        relations.append(AgentAttackSurfaceRelation(from_id=tool.server_id or "unknown-server", to_id=tool.tool_id, kind="EXPOSES"))
    for resource in sorted(system.mcp_resources, key=lambda r: r.resource_id):
        elements.append(_element("MCP_RESOURCE", resource.resource_id, component=resource.server_id))
    for prompt in sorted(system.mcp_prompts, key=lambda p: p.prompt_id):
        elements.append(_element("MCP_PROMPT", prompt.prompt_id, component=prompt.server_id))
    for delegation in sorted(system.delegations, key=lambda d: d.delegation_id):
        elements.append(_element("DELEGATION", delegation.delegation_id, agent_id=delegation.issuer))
        relations.append(AgentAttackSurfaceRelation(from_id=delegation.issuer, to_id=delegation.delegate, kind="DELEGATES_TO"))
    for identity in sorted(system.identities, key=lambda i: i.identity_id):
        elements.append(_element("IDENTITY", identity.identity_id))
    for flow in sorted(system.credential_flows, key=lambda f: f.flow_id):
        elements.append(_element("CREDENTIAL", flow.flow_id))
    for callback in sorted(system.context_sources, key=lambda c: c.source_id):
        if callback.kind in ("callback", "webhook"):
            elements.append(_element("CALLBACK" if callback.kind == "callback" else "WEBHOOK", callback.source_id))
    for endpoint in sorted(system.endpoints, key=lambda e: e.endpoint_id):
        elements.append(_element("EXTERNAL_ENDPOINT", endpoint.endpoint_id))
    seen: dict[str, AgentAttackSurfaceElement] = {}
    for element in elements:
        if element.element_id not in seen:
            seen[element.element_id] = element
    completeness = _completeness(system, bool(seen))
    if completeness in ("PARTIALLY_MAPPED", "UNKNOWN"):
        limitations.append(f"agent surface completeness: {completeness} (partial mapping is never complete mapping)")
    return AgentAttackSurface(
        audit_id=system.audit_id, project_id=system.project_id, snapshot_id=system.snapshot_id,
        elements=tuple(sorted(seen.values(), key=lambda e: e.element_id)),
        relations=tuple(sorted(relations, key=lambda r: (r.from_id, r.to_id))),
        completeness=completeness, coverage=system.coverage, limitations=tuple(limitations),
    )


def _completeness(system: AgentSystem, has_elements: bool) -> str:
    if not has_elements:
        if not (system.agents or system.mcp_servers or system.mcp_tools):
            return "UNKNOWN"
        return "NONE_OBSERVED"
    if system.coverage == "PARTIALLY_MAPPED":
        return "PARTIALLY_MAPPED"
    return "FULLY_MAPPED"
