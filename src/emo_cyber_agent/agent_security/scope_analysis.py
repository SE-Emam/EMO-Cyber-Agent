"""Scope analysis + capability graph — POST-RC-010.

Builds the Agent → Skill → Tool → Capability → Target graph from
declared bindings plus Policy/Tool/Skill/Playbook facts, then
compares DECLARED scope against EFFECTIVE scope. Widening is a
security signal. Permissions are never mutated here; the
PolicyEngine remains the only authority.
"""

from __future__ import annotations

from typing import Any


def build_capability_graph(
    system: Any,
    *,
    skill_capabilities: dict[str, tuple[str, ...]] | None = None,
    tool_capabilities: dict[str, tuple[str, ...]] | None = None,
    policy_grants: dict[str, tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    """Deterministic capability graph. Declaration vs observation vs
    effective are kept as separate edge labels."""
    skill_capabilities = skill_capabilities or {}
    tool_capabilities = tool_capabilities or {}
    policy_grants = policy_grants or {}
    nodes: dict[str, str] = {}
    edges: list[dict[str, str]] = []
    for agent in sorted(getattr(system, "agents", ()) or (), key=lambda a: a.agent_id):
        nodes[agent.agent_id] = "agent"
        for sub in sorted(getattr(system, "subagents", ()) or (), key=lambda s: s.subagent_id):
            if sub.parent_id == agent.agent_id:
                nodes[sub.subagent_id] = "subagent"
                edges.append({"from": agent.agent_id, "to": sub.subagent_id, "kind": "DELEGATED_SUBSET"})
    for binding in sorted(getattr(system, "skill_bindings", ()) or (), key=lambda b: (b.agent_id, b.skill_id)):
        nodes[binding.skill_id] = "skill"
        edges.append({"from": binding.agent_id, "to": binding.skill_id, "kind": "DECLARED_CAPABILITY"})
        for capability in sorted(skill_capabilities.get(binding.skill_id, ())):
            nodes[capability] = "capability"
            edges.append({"from": binding.skill_id, "to": capability, "kind": "OBSERVED_CAPABILITY"})
    for binding in sorted(getattr(system, "tool_bindings", ()) or (), key=lambda b: (b.agent_id, b.tool_id)):
        nodes[binding.tool_id] = "tool"
        edges.append({"from": binding.agent_id, "to": binding.tool_id, "kind": "DECLARED_CAPABILITY"})
        for capability in sorted(tool_capabilities.get(binding.tool_id, ())):
            nodes[capability] = "capability"
            edges.append({"from": binding.tool_id, "to": capability, "kind": "OBSERVED_CAPABILITY"})
    for holder in sorted(policy_grants):
        for capability in sorted(policy_grants[holder]):
            nodes[capability] = "capability"
            edges.append({"from": holder, "to": capability, "kind": "EFFECTIVE_CAPABILITY"})
    for tool in sorted(getattr(system, "mcp_tools", ()) or (), key=lambda t: t.tool_id):
        nodes[tool.tool_id] = "tool"
        for capability in sorted(tool.capabilities):
            nodes[capability] = "capability"
            edges.append({"from": tool.tool_id, "to": capability, "kind": "OBSERVED_CAPABILITY"})
    return {"nodes": nodes, "edges": edges}


def detect_scope_widening(
    declared_scope: tuple[str, ...],
    effective_capabilities: tuple[str, ...],
    *,
    subject_id: str = "",
) -> list[dict[str, Any]]:
    """Declared ≠ effective is a signal. Pure set logic; mutates nothing."""
    declared, effective = set(declared_scope), set(effective_capabilities)
    signals: list[dict[str, Any]] = []
    for capability in sorted(effective - declared):
        signals.append({"signal": "SCOPE_WIDENING", "subject_id": subject_id, "detail": f"effective capability outside declared scope: {capability}"})
    for capability in sorted(declared - effective):
        signals.append({"signal": "UNKNOWN_CAPABILITY", "subject_id": subject_id, "detail": f"declared scope without observed effect: {capability}"})
    return signals


def detect_excessive_agency(
    task_scope: tuple[str, ...],
    reachable_capabilities: tuple[str, ...],
    *,
    subject_id: str = "",
) -> list[dict[str, Any]]:
    """Read-only task reaching write-capable tooling is a signal."""
    write_like = [c for c in reachable_capabilities if any(token in c.lower() for token in ("write", "delete", "execute", "admin", "deploy"))]
    read_only = any("read-only" in s.lower() or s.strip().lower() == "read" for s in task_scope)
    if read_only and write_like:
        return [{"signal": "EXCESSIVE_AGENCY", "subject_id": subject_id, "detail": f"read-only task reaches write-capable tooling: {','.join(sorted(write_like))}"}]
    return []
