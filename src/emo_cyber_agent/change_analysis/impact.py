"""Impact propagation — POST-RC-008.

Changed symbols propagate across the relations that already exist in
Code Intelligence (calls, dataflow, endpoints, boundaries, database
relations, dependencies). Bounded, budgeted, snapshot-scoped, and
explained. Limits produce partial coverage, never false completeness.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from emo_cyber_agent.change_analysis.spec import AffectedSurface, ChangeSet, SecurityImpact

DOMAIN_SKILLS: dict[str, tuple[str, ...]] = {
    "CODE_BEHAVIOR": ("backend-security", "code-review-security"),
    "AUTHORIZATION": ("authorization",),
    "AUTHENTICATION": ("authentication",),
    "INPUT_HANDLING": ("injection",),
    "OUTPUT_HANDLING": ("frontend-security", "injection"),
    "CRYPTO": ("cryptography",),
    "SECRET_HANDLING": ("secrets",),
    "DEPENDENCY": ("dependency-security", "supply-chain"),
    "CONFIGURATION": ("configuration",),
    "NETWORK": ("api-security",),
    "FILE_ACCESS": ("backend-security",),
    "DATABASE": ("database-security",),
    "ROUTING": ("api-security",),
    "STATE_CHANGE": ("business-logic",),
    "INFRASTRUCTURE": ("infrastructure-as-code",),
}


def propagate(
    changeset: ChangeSet,
    *,
    target_graph: Any = None,
    max_hops: int = 4,
    max_nodes: int = 500,
) -> tuple[AffectedSurface, bool, list[str]]:
    """BFS from changed symbols over target-graph relations.

    Returns (surface, partial, trail). partial=True when the budget
    stopped the walk or no graph was available.
    """
    reached_symbols: set[str] = {s.symbol_id for s in changeset.symbols if s.change in ("ADDED", "MODIFIED")}
    reached_dataflow: set[str] = set()
    trail: list[str] = [f"seeds:{len(reached_symbols)}"]
    partial = False
    if target_graph is None:
        return AffectedSurface(symbols=tuple(sorted(reached_symbols))), True, trail + ["no-graph:symbol-seeds-only"]

    adjacency: dict[str, set[str]] = {}
    df_adjacency: dict[str, set[str]] = {}

    def _link(a: str, b: str) -> None:
        adjacency.setdefault(a, set()).add(b)
        adjacency.setdefault(b, set()).add(a)

    for edge in getattr(target_graph, "call_edges", []) or []:
        _link(edge.caller_id, edge.callee_id)
    for edge in getattr(target_graph, "df_edges", []) or []:
        df_adjacency.setdefault(edge.from_id, set()).add(edge.to_id)
        _link(edge.from_id, edge.to_id)
    for path in (getattr(target_graph, "taint_paths", {}) or {}).values():
        nodes = list(path.node_ids)
        for a, b in zip(nodes, nodes[1:]):
            _link(a, b)

    visited = set(reached_symbols)
    frontier: deque[tuple[str, int]] = deque((s, 0) for s in sorted(reached_symbols))
    while frontier:
        current, depth = frontier.popleft()
        if depth >= max(1, max_hops):
            continue
        for neighbor in sorted(adjacency.get(current, ())):
            if neighbor in visited:
                continue
            if len(visited) >= max(1, max_nodes):
                partial = True
                frontier.clear()
                break
            visited.add(neighbor)
            frontier.append((neighbor, depth + 1))
            if neighbor in df_adjacency or any(neighbor in targets for targets in df_adjacency.values()):
                reached_dataflow.add(neighbor)
    trail.append(f"reached:{len(visited)}")
    if partial:
        trail.append("budget-exhausted:partial-coverage")

    symbols_in_graph = set(getattr(target_graph, "symbols", {}) or {})
    reached_symbol_ids = sorted(s for s in visited if s in symbols_in_graph)
    endpoints, boundaries = _link_endpoints(target_graph, set(reached_symbol_ids))
    db_objects = _link_database(target_graph, set(reached_symbol_ids))
    dep_components = _link_dependency_files(changeset, target_graph)
    return (
        AffectedSurface(
            symbols=tuple(reached_symbol_ids), routes=tuple(endpoints), boundaries=tuple(boundaries),
            dataflow_nodes=tuple(sorted(reached_dataflow)), database_objects=tuple(db_objects), components=tuple(dep_components),
        ),
        partial,
        trail,
    )


def _link_endpoints(target_graph: Any, reached: set[str]) -> tuple[list[str], list[str]]:
    endpoints: list[str] = []
    boundaries: list[str] = []
    for eid, endpoint in sorted((getattr(target_graph, "endpoints", {}) or {}).items()):
        handler_hit = endpoint.handler_id in reached
        downstream_hit = bool(set(endpoint.downstream or ()) & reached)
        if handler_hit or downstream_hit:
            endpoints.append(eid)
            if endpoint.auth_boundary_id:
                boundaries.append(endpoint.auth_boundary_id)
    return endpoints, sorted(set(boundaries))


def _link_database(target_graph: Any, reached: set[str]) -> list[str]:
    objects: list[str] = []
    for rel in getattr(target_graph, "db_relations", []) or []:
        if rel.code_id in reached:
            objects.append(rel.database_object)
    return sorted(set(objects))


def _link_dependency_files(changeset: ChangeSet, target_graph: Any) -> list[str]:
    if target_graph is None:
        return []
    manifests = {f.path for f in changeset.files if f.state in ("ADDED", "MODIFIED", "REMOVED")}
    components: list[str] = []
    for edge in getattr(target_graph, "dep_edges", []) or []:
        if edge.manifest_path in manifests or edge.importer in manifests:
            components.append(f"{edge.package}@{edge.version or '?'}")
    return sorted(set(components))


def analyze_impact(
    changeset: ChangeSet,
    predicates_fired: dict[str, list[str]],
    surface: AffectedSurface,
    *,
    propagation_partial: bool = False,
    skill_registry: Any = None,
) -> SecurityImpact:
    domains = sorted({c for classification in changeset.classifications for c in classification.classifications if c != "UNKNOWN"})
    skills: list[str] = []
    for domain in domains:
        skills.extend(s for s in DOMAIN_SKILLS.get(domain, ()) if s not in skills)
    tools: list[str] = []
    limitations = list(changeset.limitations)
    if any("UNKNOWN" in c.classifications for c in changeset.classifications):
        limitations.append("unknown-classified changes present: not treated as unchanged or safe")
    if skill_registry is not None:
        try:
            for skill_id in skills:
                tools.extend(t for t in skill_registry.get(skill_id).allowed_tools if t not in tools)
        except Exception:
            limitations.append("tool-derivation-unavailable: skill registry lookup failed")
    else:
        limitations.append("tool-derivation-unavailable: no skill registry wired")
    if propagation_partial:
        limitations.append("propagation-budget-exhausted: partial surface coverage")
    coverage = "partial" if (propagation_partial or changeset.coverage != "complete") else "complete"
    affected = bool(domains or predicates_fired or surface.symbols or surface.routes)
    assets = [changeset.project_id] if changeset.project_id else []
    return SecurityImpact(
        affected=affected, domains=tuple(domains), affected_assets=tuple(assets),
        affected_routes=tuple(surface.routes), affected_symbols=tuple(surface.symbols),
        affected_tools=tuple(sorted(tools)), affected_skills=tuple(skills), surface=surface,
        confidence_context="structural-facts-only", coverage=coverage,
        limitations=tuple(limitations), reason_codes=tuple(sorted(predicates_fired)),
    )
