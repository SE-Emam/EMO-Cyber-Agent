"""MCP topology builder — POST-RC-010.

Normalized client/server/tool/resource/prompt topology with
explicit trust relationships and version-scoped protocol facts.
No connections, no invocations, no credential forwarding.
Protocol assumptions are version-scoped: unknown versions yield
UNKNOWN metadata plus a limitation, never hard-coded behavior.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.agent_security.spec import AgentSystem

# Protocol versions this layer has explicit notes for. Anything
# else is carried as data with UNKNOWN assumptions.
KNOWN_PROTOCOL_VERSIONS: tuple[str, ...] = ("2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28")


def build_mcp_topology(system: AgentSystem) -> dict[str, Any]:
    servers = {s.server_id: s for s in system.mcp_servers}
    relations: list[dict[str, str]] = []
    limitations: list[str] = []
    for client in sorted(system.mcp_clients, key=lambda c: c.client_id):
        if client.server_id and client.server_id in servers:
            relations.append({"from": client.client_id, "to": client.server_id, "kind": "CALLS"})
        elif client.server_id:
            limitations.append(f"client {client.client_id} references unknown server {client.server_id}")
    for tool in sorted(system.mcp_tools, key=lambda t: t.tool_id):
        if tool.server_id in servers:
            relations.append({"from": tool.server_id, "to": tool.tool_id, "kind": "EXPOSES"})
        relations.append({"from": tool.tool_id, "to": tool.server_id or "unknown-server", "kind": "DESCRIBES"})
    for resource in sorted(system.mcp_resources, key=lambda r: r.resource_id):
        if resource.server_id in servers:
            relations.append({"from": resource.server_id, "to": resource.resource_id, "kind": "EXPOSES"})
            relations.append({"from": resource.resource_id, "to": resource.server_id, "kind": "RETURNS_DATA_TO"})
    for prompt in sorted(system.mcp_prompts, key=lambda p: p.prompt_id):
        if prompt.server_id in servers:
            relations.append({"from": prompt.server_id, "to": prompt.prompt_id, "kind": "EXPOSES"})
            relations.append({"from": prompt.prompt_id, "to": prompt.server_id, "kind": "SUPPLIES_CONTEXT_TO"})
    for agent in sorted(system.agents, key=lambda a: a.agent_id):
        for client in sorted(system.mcp_clients, key=lambda c: c.client_id):
            if client.agent_id == agent.agent_id:
                relations.append({"from": agent.agent_id, "to": client.client_id, "kind": "DELEGATES_TO"})
    protocol_notes: dict[str, str] = {}
    for server in sorted(system.mcp_servers, key=lambda s: s.server_id):
        version = server.protocol_version or "unknown"
        if version in KNOWN_PROTOCOL_VERSIONS:
            protocol_notes[server.server_id] = f"version-scoped facts for {version}"
        else:
            protocol_notes[server.server_id] = "unknown protocol version: assumptions UNKNOWN"
            limitations.append(f"server {server.server_id} uses unknown protocol version {version}; behavior assumptions UNKNOWN")
    return {"relations": relations, "protocol_notes": protocol_notes, "limitations": limitations}
