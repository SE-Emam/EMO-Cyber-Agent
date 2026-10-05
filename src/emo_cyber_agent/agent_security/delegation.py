"""Delegation analysis — POST-RC-010.

Structural checks over declared delegations: scope widening,
confused deputy shapes, identity confusion, cross-tenant drift,
credential propagation, expiry awareness. Findings-shaped
outputs are signals, never permissions.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.agent_security.identity import widened_scopes


def analyze_delegations(system: Any) -> list[dict[str, Any]]:
    """Return deterministic delegation signals for an agent system."""
    signals: list[dict[str, Any]] = []
    delegations = list(getattr(system, "delegations", ()) or ())
    subagents = {s.subagent_id: s for s in (getattr(system, "subagents", ()) or ())}
    agents = {a.agent_id: a for a in (getattr(system, "agents", ()) or ())}
    parent_scopes: dict[str, tuple[str, ...]] = {}
    for delegation in sorted(delegations, key=lambda d: d.delegation_id):
        parent_scopes.setdefault(delegation.issuer, ())
        if delegation.issuer in parent_scopes and parent_scopes[delegation.issuer]:
            widened = widened_scopes(parent_scopes[delegation.issuer], delegation.scope)
        else:
            widened = []
        parent_scopes[delegation.delegate] = tuple(delegation.scope)
        if widened:
            signals.append({"signal": "SCOPE_WIDENING", "delegation_id": delegation.delegation_id, "detail": f"delegate scope exceeds issuer scope: {','.join(widened)}"})
        child = subagents.get(delegation.delegate)
        parent = agents.get(delegation.issuer, subagents.get(delegation.issuer))
        if child is not None and parent is not None:
            parent_tools = set(getattr(parent, "tool_ids", ()))
            child_tools = set(getattr(child, "tool_ids", ()))
            outside = sorted(child_tools - parent_tools)
            if outside:
                signals.append({"signal": "PRIVILEGE_INHERITANCE", "delegation_id": delegation.delegation_id, "detail": f"child holds tools outside parent set (no automatic inheritance): {','.join(outside)}"})
        if not delegation.audience:
            signals.append({"signal": "UNSCOPED_DELEGATION", "delegation_id": delegation.delegation_id, "detail": "delegation carries no audience restriction"})
        if not delegation.validity:
            signals.append({"signal": "UNBOUNDED_DELEGATION", "delegation_id": delegation.delegation_id, "detail": "delegation carries no validity window"})
        issuer_identity = next((i for i in (getattr(system, "identities", ()) or ()) if i.identity_id == getattr(parent, "identity_id", "")), None) if parent is not None else None
        child_identity = next((i for i in (getattr(system, "identities", ()) or ()) if i.identity_id == getattr(child, "identity_id", "")), None) if child is not None else None
        if issuer_identity is not None and child_identity is not None and issuer_identity.identity_id == child_identity.identity_id and issuer_identity.kind != child_identity.kind:
            signals.append({"signal": "IDENTITY_CONFUSION", "delegation_id": delegation.delegation_id, "detail": "same identity principal recorded under different kinds"})
        if "tenant" in delegation.audience.lower() or "tenant" in ",".join(delegation.scope).lower():
            signals.append({"signal": "CROSS_TENANT_DELEGATION", "delegation_id": delegation.delegation_id, "detail": "delegation text references tenant crossing; verify tenant isolation downstream"})
    return signals
