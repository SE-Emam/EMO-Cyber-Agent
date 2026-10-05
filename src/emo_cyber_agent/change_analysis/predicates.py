"""Security-aware diff predicates — POST-RC-008.

Twelve deterministic signals evaluated from the ChangeSet plus the
base/target code graphs. Signals, never findings: a fired predicate
requests targeted review, it does not assert a vulnerability.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.change_analysis.spec import ChangeSet


def _base_ids(graph: Any, attr: str) -> set[str]:
    return set(getattr(graph, attr, {}) or {}) if graph is not None else set()


def _target_ids(graph: Any, attr: str) -> set[str]:
    return set(getattr(graph, attr, {}) or {}) if graph is not None else set()


def _eval_auth_boundary_changed(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    refs: list[str] = []
    if any(r.auth_boundary_changed for r in changeset.routes):
        refs.extend(f"route:{r.endpoint_id}" for r in changeset.routes if r.auth_boundary_changed)
        return True, refs
    if base_graph is None or target_graph is None:
        return False, []
    base_b = _base_ids(base_graph, "boundaries")
    target_b = _target_ids(target_graph, "boundaries")
    changed_paths = {f.path for f in changeset.files if f.state in ("ADDED", "MODIFIED")}
    touched = [bid for bid in (target_b - base_b) | (base_b - target_b)]
    refs = [f"boundary:{bid}" for bid in sorted(touched)]
    boundary_files = set()
    for bid in touched:
        boundary = (getattr(target_graph, "boundaries", {}) or {}).get(bid) or (getattr(base_graph, "boundaries", {}) or {}).get(bid)
        if boundary is not None and boundary.location.path in changed_paths:
            boundary_files.add(boundary.location.path)
    if touched and boundary_files:
        return True, refs
    return False, []


def _eval_state_change_added(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    refs = [f"route:{r.endpoint_id}" for r in changeset.routes if r.change == "ADDED"]
    if refs or any(r.change == "ADDED" for r in changeset.routes):
        return bool(refs), refs
    if target_graph is None:
        return False, []
    base_eps = _base_ids(base_graph, "endpoints")
    new_stateful = [eid for eid, ep in sorted(getattr(target_graph, "endpoints", {}).items()) if eid not in base_eps and ep.state_changing]
    return bool(new_stateful), [f"route:{eid}" for eid in new_stateful]


def _eval_new_external_input(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    external = ("http_parameter", "request_body", "header", "cookie", "external_input", "message_queue", "file_input")
    if target_graph is None:
        return False, []
    base_sources = {s for s in _base_ids(base_graph, "sources")}
    new = [sid for sid, src in sorted(getattr(target_graph, "sources", {}).items()) if sid not in base_sources and src.kind in external]
    return bool(new), [f"source:{sid}" for sid in new]


def _eval_new_sink(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    if target_graph is None:
        return False, []
    base_sinks = _base_ids(base_graph, "sinks")
    new = sorted(set(getattr(target_graph, "sinks", {})) - base_sinks)
    return bool(new), [f"sink:{sid}" for sid in new]


def _taint_pairs(graph: Any) -> dict[tuple[str, str], frozenset[str]]:
    pairs: dict[tuple[str, str], frozenset[str]] = {}
    if graph is None:
        return pairs
    for pid, path in sorted(getattr(graph, "taint_paths", {}).items()):
        pairs[(path.source_id, path.sink_id)] = frozenset(path.node_ids)
    return pairs


def _eval_new_taint_path(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    if target_graph is None:
        return False, []
    base_pairs = set(_taint_pairs(base_graph))
    new = sorted(set(_taint_pairs(target_graph)) - base_pairs)
    return bool(new), [f"taint:{src}->{snk}" for src, snk in new]


def _eval_taint_path_modified(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    if base_graph is None or target_graph is None:
        return False, []
    base_pairs, target_pairs = _taint_pairs(base_graph), _taint_pairs(target_graph)
    modified = sorted(pair for pair in set(base_pairs) & set(target_pairs) if base_pairs[pair] != target_pairs[pair])
    return bool(modified), [f"taint:{src}->{snk}" for src, snk in modified]


def _eval_route_permission_changed(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    refs = [f"route:{r.endpoint_id}" for r in changeset.routes if r.change == "MODIFIED" and r.auth_boundary_changed]
    return bool(refs), refs


def _eval_dependency_version_changed(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    refs = [f"dependency:{d.package}@{d.current_version or '?'}"
            for d in changeset.dependencies if d.previous_version != d.current_version]
    return bool(refs), refs


def _eval_secret_handling_changed(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    refs = sorted({f"file:{f.path}" for f in changeset.files if "SECRET_HANDLING" in f.classifications and f.state in ("ADDED", "MODIFIED")})
    return bool(refs), refs


def _eval_file_access_changed(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    refs = sorted({f"file:{f.path}" for f in changeset.files if "FILE_ACCESS" in f.classifications and f.state in ("ADDED", "MODIFIED")})
    if target_graph is not None:
        base_sink_objs = getattr(base_graph, "sinks", {}) or {} if base_graph is not None else {}
        target_sink_objs = getattr(target_graph, "sinks", {}) or {}
        new_fs = sorted(sid for sid, s in target_sink_objs.items() if sid not in base_sink_objs and s.kind == "filesystem")
        refs = sorted(set(refs) | {f"sink:{sid}" for sid in new_fs})
    return bool(refs), refs


def _eval_database_access_changed(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    refs = [f"db:{r.relation_id}" for r in changeset.database_relations if r.change in ("ADDED", "REMOVED")]
    return bool(refs), refs


def _eval_config_security_change(changeset: ChangeSet, base_graph: Any, target_graph: Any) -> tuple[bool, list[str]]:
    refs = sorted({f"file:{f.path}" for f in changeset.files if "CONFIGURATION" in f.classifications and f.state in ("ADDED", "MODIFIED")})
    return bool(refs), refs


_PREDICATE_FNS = {
    "AUTH_BOUNDARY_CHANGED": _eval_auth_boundary_changed,
    "STATE_CHANGE_ADDED": _eval_state_change_added,
    "NEW_EXTERNAL_INPUT": _eval_new_external_input,
    "NEW_SINK": _eval_new_sink,
    "NEW_TAINT_PATH": _eval_new_taint_path,
    "TAINT_PATH_MODIFIED": _eval_taint_path_modified,
    "ROUTE_PERMISSION_CHANGED": _eval_route_permission_changed,
    "DEPENDENCY_VERSION_CHANGED": _eval_dependency_version_changed,
    "SECRET_HANDLING_CHANGED": _eval_secret_handling_changed,
    "FILE_ACCESS_CHANGED": _eval_file_access_changed,
    "DATABASE_ACCESS_CHANGED": _eval_database_access_changed,
    "CONFIG_SECURITY_CHANGE": _eval_config_security_change,
}


def evaluate_predicates(changeset: ChangeSet, *, base_graph: Any = None, target_graph: Any = None) -> dict[str, list[str]]:
    """Evaluate all 12 predicates deterministically. Returns only fired
    predicates mapped to evidence references."""
    fired: dict[str, list[str]] = {}
    for name in sorted(_PREDICATE_FNS):
        hit, refs = _PREDICATE_FNS[name](changeset, base_graph, target_graph)
        if hit:
            fired[name] = refs
    return fired
