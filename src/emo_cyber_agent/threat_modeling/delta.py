"""Threat model delta — POST-RC-009.

Snapshot-to-snapshot comparison of threat models. A disappeared
scenario is REMOVED_SCENARIO — presence metadata only. It is never
a resolved vulnerability and never touches Finding lifecycle.
"""

from __future__ import annotations

from emo_cyber_agent.threat_modeling.errors import ThreatModelError, ThreatModelErrorCode
from emo_cyber_agent.threat_modeling.spec import ThreatDeltaEntry, ThreatModel, ThreatModelDelta


def diff_threat_models(base: ThreatModel, target: ThreatModel) -> ThreatModelDelta:
    if base.audit_id != target.audit_id:
        raise ThreatModelError(ThreatModelErrorCode.CROSS_AUDIT, "threat models belong to different audits")
    if base.snapshot_id == target.snapshot_id:
        raise ThreatModelError(ThreatModelErrorCode.INVALID, "identical snapshot ids: nothing to compare")
    entries: list[ThreatDeltaEntry] = []
    base_scenarios = {s.scenario_id: s for s in base.scenarios}
    target_scenarios = {s.scenario_id: s for s in target.scenarios}
    for sid in sorted(set(target_scenarios) - set(base_scenarios)):
        entries.append(ThreatDeltaEntry(kind="NEW_THREAT_SCENARIO", subject_id=sid, detail="scenario present in target only"))
    for sid in sorted(set(base_scenarios) - set(target_scenarios)):
        entries.append(ThreatDeltaEntry(kind="REMOVED_SCENARIO", subject_id=sid, detail="scenario absent from target snapshot; presence metadata only, never a resolved vulnerability"))
    for sid in sorted(set(base_scenarios) & set(target_scenarios)):
        before, after = base_scenarios[sid], target_scenarios[sid]
        if before.model_dump(mode="json") == after.model_dump(mode="json"):
            entries.append(ThreatDeltaEntry(kind="PERSISTING_SCENARIO", subject_id=sid))
        else:
            entries.append(ThreatDeltaEntry(kind="CHANGED_SCENARIO", subject_id=sid, detail="scenario record differs between snapshots"))
    base_surface = {e.element_id for e in base.surface.elements} if base.surface else set()
    target_surface = {e.element_id for e in target.surface.elements} if target.surface else set()
    for eid in sorted(target_surface - base_surface):
        entries.append(ThreatDeltaEntry(kind="NEW_ATTACK_SURFACE", subject_id=eid))
    for eid in sorted(base_surface - target_surface):
        entries.append(ThreatDeltaEntry(kind="REMOVED_ATTACK_SURFACE", subject_id=eid))
    base_boundaries = {b.boundary_id: b for b in base.system.boundaries} if base.system else {}
    target_boundaries = {b.boundary_id: b for b in target.system.boundaries} if target.system else {}
    for bid in sorted(set(target_boundaries) & set(base_boundaries)):
        if base_boundaries[bid].model_dump(mode="json") != target_boundaries[bid].model_dump(mode="json"):
            entries.append(ThreatDeltaEntry(kind="CHANGED_BOUNDARY", subject_id=bid))
    base_controls = {c.control_id for c in base.controls}
    target_controls = {c.control_id for c in target.controls}
    for cid in sorted((target_controls - base_controls) | (base_controls - target_controls)):
        entries.append(ThreatDeltaEntry(kind="CHANGED_CONTROL", subject_id=cid))
    coverage_change = ""
    if base.coverage.model_dump(mode="json") != target.coverage.model_dump(mode="json"):
        coverage_change = f"{base.coverage.endpoints}->{target.coverage.endpoints} endpoints"
        entries.append(ThreatDeltaEntry(kind="COVERAGE_CHANGE", detail=coverage_change))
    return ThreatModelDelta(
        audit_id=base.audit_id, base_snapshot_id=base.snapshot_id, target_snapshot_id=target.snapshot_id,
        entries=tuple(entries), coverage_change=coverage_change,
        limitations=("removed scenarios describe snapshot presence only; never Finding lifecycle",),
    )
