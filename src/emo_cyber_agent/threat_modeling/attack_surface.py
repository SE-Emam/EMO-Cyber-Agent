"""Attack surface map — POST-RC-009.

Independent, queryable surface facts: every element links asset,
project, snapshot, component, route/symbol where available,
evidence, provenance, coverage, and limitations. Surface facts
are not findings: an AUTHORIZATION surface never claims an
authorization vulnerability.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.threat_modeling.provenance import build_threat_provenance
from emo_cyber_agent.threat_modeling.spec import (
    AttackSurface,
    AttackSurfaceElement,
    AttackSurfaceRelation,
    SystemModel,
)


def _slug(text: str) -> str:
    import re as _re

    slug = _re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug[:80] or "unnamed"


def build_attack_surface(
    system: SystemModel,
    *,
    code_graph: Any = None,
    codeintel_capabilities: tuple[str, ...] = (),
    secret_symbols: tuple[str, ...] = (),
    evidence_index: dict[str, tuple[str, ...]] | None = None,
) -> AttackSurface:
    evidence_index = evidence_index or {}
    limitations: list[str] = list(system.limitations)
    elements: list[AttackSurfaceElement] = []
    relations: list[AttackSurfaceRelation] = []

    def _element(category: str, subject: str, **links: Any) -> AttackSurfaceElement:
        return AttackSurfaceElement(
            element_id=f"surface-{_slug(category)}-{_slug(subject)}", category=category,
            asset_id=system.project_id, project_id=system.project_id, snapshot_id=system.snapshot_id,
            evidence_ids=tuple(evidence_index.get(subject, ())),
            provenance=build_threat_provenance(
                audit_id=system.audit_id, project_id=system.project_id, snapshot_id=system.snapshot_id,
                subject_id=subject, coverage=system.coverage,
            ),
            coverage=system.coverage, limitations=(),
            **{k: v for k, v in links.items() if v},
        )

    endpoints_by_id: dict[str, Any] = {}
    state_changing: set[str] = set()
    if code_graph is not None:
        for eid, endpoint in sorted((getattr(code_graph, "endpoints", {}) or {}).items()):
            endpoints_by_id[eid] = endpoint
            if endpoint.state_changing:
                state_changing.add(eid)
    boundary_by_entry: dict[str, str] = {}
    if code_graph is not None:
        for bid, boundary in sorted((getattr(code_graph, "boundaries", {}) or {}).items()):
            if boundary.protects_id:
                boundary_by_entry[boundary.protects_id] = bid
    for entry in system.entries:
        elements.append(_element("INBOUND", entry.entry_id, component_id=_component_for(entry.handler, system), route_id=entry.route_id, symbol_id=entry.handler))
        relations.append(AttackSurfaceRelation(from_id="actor-external-user", to_id=f"surface-inbound-{_slug(entry.entry_id)}", kind="reaches"))
        auth_known = bool(boundary_by_entry.get(entry.handler)) or any(b.protects and entry.handler in b.protects for b in system.boundaries)
        if auth_known:
            elements.append(_element("AUTHORIZATION", entry.entry_id, component_id=_component_for(entry.handler, system), route_id=entry.route_id, symbol_id=entry.handler))
            elements.append(_element("AUTHENTICATION", entry.entry_id, component_id=_component_for(entry.handler, system), route_id=entry.route_id, symbol_id=entry.handler))
        if entry.entry_id in {_slug_to_entry(eid) for eid in state_changing} or _is_state_changing(entry.entry_id, endpoints_by_id):
            elements.append(_element("STATE_CHANGE", entry.entry_id, component_id=_component_for(entry.handler, system), route_id=entry.route_id, symbol_id=entry.handler))
        if "admin" in entry.path.lower():
            elements.append(_element("ADMINISTRATIVE", entry.entry_id, route_id=entry.route_id, symbol_id=entry.handler))
    for exit_point in system.exits:
        if exit_point.kind in ("network_request",):
            elements.append(_element("OUTBOUND", exit_point.exit_id, symbol_id=exit_point.sink_id))
            elements.append(_element("NETWORK_ACCESS", exit_point.exit_id, symbol_id=exit_point.sink_id))
        elif exit_point.kind in ("filesystem",):
            elements.append(_element("FILE_ACCESS", exit_point.exit_id, symbol_id=exit_point.sink_id))
        elif exit_point.kind in ("html_rendering", "template_engine"):
            elements.append(_element("OUTBOUND", exit_point.exit_id, symbol_id=exit_point.sink_id))
    for flow in system.flows:
        if flow.kind == "data-access":
            elements.append(_element("DATA_ACCESS", flow.flow_id, component_id=_component_for(flow.source, system)))
            elements.append(_element("DATABASE_ACCESS", flow.flow_id, component_id=_component_for(flow.source, system)))
    for symbol in secret_symbols:
        elements.append(_element("SECRET_ACCESS", f"secret-{_slug(symbol)}", symbol_id=symbol))
    if not secret_symbols:
        limitations.append("secret-access: no secret evidence supplied; category omitted rather than assumed empty")
    seen: dict[str, AttackSurfaceElement] = {}
    for element in elements:
        if element.element_id not in seen:
            seen[element.element_id] = element
    completeness = _completeness(system, code_graph, codeintel_capabilities)
    if completeness in ("PARTIALLY_MAPPED", "UNKNOWN") and completeness not in limitations:
        limitations.append(f"attack-surface completeness: {completeness} (partial mapping is never complete mapping)")
    return AttackSurface(
        audit_id=system.audit_id, project_id=system.project_id, snapshot_id=system.snapshot_id,
        elements=tuple(sorted(seen.values(), key=lambda e: e.element_id)),
        relations=tuple(sorted(relations, key=lambda r: (r.from_id, r.to_id))),
        completeness=completeness, coverage=system.coverage, limitations=tuple(limitations),
    )


def _component_for(symbol_id: str, system: SystemModel) -> str:
    for component in system.components:
        if symbol_id and symbol_id in component.symbols:
            return component.component_id
    return ""


def _slug_to_entry(eid: str) -> str:
    return f"entry-{_slug(eid)}"


def _is_state_changing(entry_id: str, endpoints_by_id: dict[str, Any]) -> bool:
    for eid, endpoint in endpoints_by_id.items():
        if _slug_to_entry(eid) == entry_id and endpoint.state_changing:
            return True
    return False


def _completeness(system: SystemModel, code_graph: Any, codeintel_capabilities: tuple[str, ...]) -> str:
    truncated = bool(code_graph is not None and getattr(code_graph, "truncated", False))
    has_routes_cap = "routes" in codeintel_capabilities
    has_entries = bool(system.entries)
    if code_graph is None:
        return "UNKNOWN"
    if truncated:
        return "PARTIALLY_MAPPED"
    if not has_entries:
        return "NONE_OBSERVED" if has_routes_cap else "UNKNOWN"
    if not codeintel_capabilities:
        return "PARTIALLY_MAPPED"
    return "FULLY_MAPPED"
