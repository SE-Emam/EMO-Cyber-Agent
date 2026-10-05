"""Agent security delta — POST-RC-009/010 companion.

Snapshot-to-snapshot comparison of agent systems, surfaces, and
scenarios. Disappearance is a presence fact, never a resolved
vulnerability and never a Finding lifecycle transition.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.agent_security.errors import AgentSecurityError, AgentSecurityErrorCode
from emo_cyber_agent.agent_security.spec import AgentThreatDelta


def diff_agent_models(base: Any, target: Any) -> AgentThreatDelta:
    if base.audit_id != target.audit_id:
        raise AgentSecurityError(AgentSecurityErrorCode.CROSS_AUDIT, "agent models belong to different audits")
    if base.snapshot_id == target.snapshot_id:
        raise AgentSecurityError(AgentSecurityErrorCode.INVALID, "identical snapshot ids: nothing to compare")
    entries: list[dict[str, Any]] = []
    base_surface = {e.element_id for e in (base.surface.elements if getattr(base, "surface", None) else ())}
    target_surface = {e.element_id for e in (target.surface.elements if getattr(target, "surface", None) else ())}
    for eid in sorted(target_surface - base_surface):
        entries.append({"kind": "NEW_ATTACK_SURFACE", "subject_id": eid})
    for eid in sorted(base_surface - target_surface):
        entries.append({"kind": "REMOVED_ATTACK_SURFACE", "subject_id": eid, "detail": "presence metadata only; never a resolved vulnerability"})
    base_scenarios = {s.scenario_id for s in getattr(base, "scenarios", ())}
    target_scenarios = {s.scenario_id for s in getattr(target, "scenarios", ())}
    for sid in sorted(target_scenarios - base_scenarios):
        entries.append({"kind": "NEW_THREAT_SCENARIO", "subject_id": sid})
    for sid in sorted(base_scenarios - target_scenarios):
        entries.append({"kind": "REMOVED_THREAT_SCENARIO", "subject_id": sid, "detail": "presence metadata only; never a resolved vulnerability"})
    base_boundaries = {b.boundary_id for b in (base.system.boundaries if getattr(base, "system", None) else ())}
    target_boundaries = {b.boundary_id for b in (target.system.boundaries if getattr(target, "system", None) else ())}
    for bid in sorted((target_boundaries - base_boundaries) | (base_boundaries - target_boundaries)):
        entries.append({"kind": "CHANGED_BOUNDARY", "subject_id": bid})
    return AgentThreatDelta(
        audit_id=base.audit_id, base_snapshot_id=base.snapshot_id, target_snapshot_id=target.snapshot_id,
        entries=tuple(entries),
        limitations=("removed entries describe snapshot presence only; never Finding lifecycle",),
    )
