"""System model builder — POST-RC-009.

Normalized DFD-like representation derived from Code Intelligence
facts plus caller-declared assets/boundaries. No boundary is
inferred from filenames; every non-OBSERVED boundary carries
provenance. No vendor lock-in: plain frozen models.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.threat_modeling.errors import ThreatModelError, ThreatModelErrorCode
from emo_cyber_agent.threat_modeling.spec import (
    EntryPoint,
    ExitPoint,
    SystemActor,
    SystemAsset,
    SystemComponent,
    SystemDataFlow,
    SystemDataStore,
    SystemModel,
    SystemProcess,
    TrustBoundary,
)


def _slug(text: str) -> str:
    import re as _re

    slug = _re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug[:80] or "unnamed"


def build_system_model(
    *,
    audit_id: str,
    project_id: str = "",
    snapshot_id: str,
    code_graph: Any = None,
    declared_assets: tuple[dict[str, Any], ...] = (),
    declared_boundaries: tuple[dict[str, Any], ...] = (),
    declared_actors: tuple[dict[str, Any], ...] = (),
) -> SystemModel:
    if not audit_id or not snapshot_id:
        raise ThreatModelError(ThreatModelErrorCode.INVALID, "audit_id and snapshot_id required")
    limitations: list[str] = []
    actors = [SystemActor(actor_id="external-user", name="External user", kind="external-user")]
    for index, raw in enumerate(declared_actors):
        name = str(raw.get("name", f"actor-{index}"))
        actors.append(SystemActor(actor_id=f"declared-{_slug(name)}", name=name[:160], kind=str(raw.get("kind", "declared"))[:60]))
    components: dict[str, SystemComponent] = {}
    processes: dict[str, SystemProcess] = {}
    assets: dict[str, SystemAsset] = {}
    stores: dict[str, SystemDataStore] = {}
    flows: list[SystemDataFlow] = []
    boundaries: list[TrustBoundary] = []
    entries: list[EntryPoint] = []
    exits: list[ExitPoint] = []
    coverage = "NOT_ANALYZED"
    if code_graph is not None:
        _require_graph_scope(code_graph, audit_id)
        symbols = getattr(code_graph, "symbols", {}) or {}
        by_file: dict[str, list[str]] = {}
        for sid, symbol in sorted(symbols.items()):
            by_file.setdefault(symbol.file, []).append(sid)
        for path in sorted(by_file):
            cid = f"component-{_slug(path)}"
            components[cid] = SystemComponent(component_id=cid, kind="module", name=path[:200], symbols=tuple(sorted(by_file[path])))
        endpoints = getattr(code_graph, "endpoints", {}) or {}
        for eid, endpoint in sorted(endpoints.items()):
            entry_id = f"entry-{_slug(eid)}"
            entries.append(EntryPoint(entry_id=entry_id, route_id=eid, method=endpoint.method, path=endpoint.path, handler=endpoint.handler_id))
            handler_file = (endpoint.handler_id.rsplit(":", 1)[0] if ":" in endpoint.handler_id else "")
            pid = f"process-{_slug(endpoint.handler_id or eid)}"
            if endpoint.handler_id and pid not in processes:
                processes[pid] = SystemProcess(process_id=pid, name=endpoint.handler_id[:200], symbols=(endpoint.handler_id,))
            for downstream in sorted(endpoint.downstream or ()):
                flows.append(SystemDataFlow(flow_id=f"flow-{_slug(eid)}-to-{_slug(downstream)}", source=endpoint.handler_id or entry_id, target=downstream, kind="call"))
            _ = handler_file
        code_boundaries = getattr(code_graph, "boundaries", {}) or {}
        for bid, boundary in sorted(code_boundaries.items()):
            boundaries.append(TrustBoundary(
                boundary_id=f"boundary-{_slug(bid)}", kind="AUTHORIZATION", basis="OBSERVED",
                provenance={"code_boundary_id": bid, "mechanism": boundary.mechanism, "location": boundary.location.model_dump(mode="json")},
                protects=(boundary.protects_id,) if boundary.protects_id else (),
            ))
        for sid, source in sorted((getattr(code_graph, "sources", {}) or {}).items()):
            flows.append(SystemDataFlow(flow_id=f"flow-src-{_slug(sid)}", source=f"external-input:{source.kind}", target=source.symbol_id or sid, kind="input"))
        for sid, sink in sorted((getattr(code_graph, "sinks", {}) or {}).items()):
            exit_id = f"exit-{_slug(sid)}"
            exits.append(ExitPoint(exit_id=exit_id, sink_id=sid, kind=sink.kind))
            flows.append(SystemDataFlow(flow_id=f"flow-{_slug(sid)}", source=sink.symbol_id or sid, target=exit_id, kind="output"))
        for rel in getattr(code_graph, "db_relations", []) or []:
            store_id = f"store-{_slug(rel.database_object)}"
            if store_id not in stores:
                stores[store_id] = SystemDataStore(store_id=store_id, name=rel.database_object[:200], kind="database")
            flows.append(SystemDataFlow(flow_id=f"flow-{_slug(rel.relation_id)}", source=rel.code_id, target=store_id, kind="data-access"))
            asset_id = f"asset-{_slug(rel.database_object)}"
            if asset_id not in assets:
                assets[asset_id] = SystemAsset(asset_id=asset_id, name=rel.database_object[:200], kind="data", provenance_kind="OBSERVED", provenance={"relation_id": rel.relation_id})
        coverage = "PARTIALLY_MAPPED" if getattr(code_graph, "truncated", False) else "FULLY_MAPPED"
        if getattr(code_graph, "truncated", False):
            limitations.append("code graph truncated: system model is partial")
    else:
        limitations.append("no code intelligence graph: system model from declarations only")
    for index, raw in enumerate(declared_assets):
        name = str(raw.get("name", f"asset-{index}"))
        aid = f"declared-asset-{_slug(name)}"
        assets[aid] = SystemAsset(asset_id=aid, name=name[:200], kind=str(raw.get("kind", "data"))[:60], provenance_kind="DECLARED", provenance={"declared_by": str(raw.get("declared_by", "caller"))[:120]})
    for index, raw in enumerate(declared_boundaries):
        kind = str(raw.get("kind", "TRUST"))
        bid = f"declared-boundary-{_slug(kind)}-{index}"
        basis = str(raw.get("basis", "DECLARED"))
        if basis not in ("OBSERVED", "INFERRED", "DECLARED", "UNKNOWN"):
            raise ThreatModelError(ThreatModelErrorCode.INVALID, f"boundary basis not allowed: {basis}")
        if basis != "OBSERVED" and not raw.get("provenance"):
            raise ThreatModelError(ThreatModelErrorCode.INVALID, "non-OBSERVED boundary requires provenance")
        boundaries.append(TrustBoundary(boundary_id=bid, kind=kind, basis=basis, provenance=dict(raw.get("provenance", {})), protects=tuple(raw.get("protects", []))))
    if not components and not entries and not assets:
        coverage = "NOT_ANALYZED" if coverage == "NOT_ANALYZED" else coverage
        limitations.append("empty system model: no components, entries, or assets")
    return SystemModel(
        audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id,
        actors=tuple(actors), components=tuple(sorted(components.values(), key=lambda c: c.component_id)),
        assets=tuple(sorted(assets.values(), key=lambda a: a.asset_id)),
        stores=tuple(sorted(stores.values(), key=lambda s: s.store_id)),
        processes=tuple(sorted(processes.values(), key=lambda p: p.process_id)),
        flows=tuple(flows), boundaries=tuple(boundaries), entries=tuple(entries), exits=tuple(exits),
        coverage=coverage, limitations=tuple(limitations),
    )


def _require_graph_scope(code_graph: Any, audit_id: str) -> None:
    snapshot = getattr(code_graph, "snapshot", None)
    project = getattr(snapshot, "project", None)
    if project is None or project.audit_id != audit_id:
        raise ThreatModelError(ThreatModelErrorCode.CROSS_AUDIT, "code graph bound to a different audit")
