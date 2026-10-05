"""Snapshot comparison — POST-RC-008.

Operates on normalized ComparisonSnapshot inputs (file maps supplied
by the caller from Repository + Code Intelligence contracts). No git
client, no child processes, no shell. Binary or uncomparable content
becomes UNKNOWN — never silently UNCHANGED.
"""

from __future__ import annotations

import difflib
import hashlib
from typing import Any

from emo_cyber_agent.change_analysis.errors import ChangeError, ChangeErrorCode
from emo_cyber_agent.change_analysis.spec import (
    ChangeClassification,
    ChangeSet,
    ChangedDatabaseRelation,
    ChangedDependency,
    ChangedFile,
    ChangedRegion,
    ChangedRoute,
    ChangedSymbol,
    ComparisonSnapshot,
    canonical_digest,
)

GENERATED_MARKERS: tuple[str, ...] = (
    "node_modules/", "vendor/", "dist/", "build/", "__pycache__/",
    ".min.js", ".pyc",
)

_AUTH_WORDS = ("auth", "login", "session", "token", "password", "oauth", "mfa", "jwt")
_CRYPTO_WORDS = ("crypto", "cipher", "encrypt", "decrypt", "hash", "tls", "ssl")
_SECRET_WORDS = ("secret", "credential", "passwd", "apikey", "api_key")
_NETWORK_WORDS = ("http", "request", "fetch", "socket", "url", "client")
_FILE_WORDS = ("fs", "file", "path", "upload", "download")
_DB_WORDS = ("db", "database", "sql", "query", "repository", "model", "migration", "schema")
_CONFIG_SUFFIXES = (".yaml", ".yml", ".toml", ".ini", ".cfg", ".env")
_CONFIG_NAMES = ("dockerfile", "docker-compose", "config")
_INFRA_WORDS = ("terraform", "k8s", "kubernetes", "helm")
_INPUT_WORDS = ("input", "valid", "sanit", "param")
_OUTPUT_WORDS = ("render", "template", "output", "view", "html", "encode")
_AUTHZ_WORDS = ("authoriz", "ownership", "role", "policy", "permission", "check", "guard")
_MANIFEST_NAMES = ("requirements.txt", "package.json", "package-lock.json", "pyproject.toml", "cargo.toml", "go.mod", "gemfile", "pom.xml")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _is_binary(content: str) -> bool:
    return "\x00" in content


def _is_generated(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in GENERATED_MARKERS)


def _is_manifest(path: str) -> bool:
    return path.lower().rsplit("/", 1)[-1] in _MANIFEST_NAMES


def _words_of(path: str, symbol: str = "") -> str:
    return f"{path.lower()} {symbol.lower()}"


def classify_path(path: str, *, state: str) -> set[str]:
    """Deterministic file-level classification from normalized facts."""
    lowered = path.lower()
    base = lowered.rsplit("/", 1)[-1]
    tags: set[str] = set()
    if _is_manifest(path):
        tags.add("DEPENDENCY")
    if any(w in lowered for w in _AUTH_WORDS):
        tags.add("AUTHENTICATION")
    if any(w in lowered for w in _CRYPTO_WORDS):
        tags.add("CRYPTO")
    if any(w in lowered for w in _SECRET_WORDS) or base == ".env":
        tags.add("SECRET_HANDLING")
    if any(w in lowered for w in _NETWORK_WORDS):
        tags.add("NETWORK")
    if any(w in lowered for w in _FILE_WORDS):
        tags.add("FILE_ACCESS")
    if any(w in lowered for w in _DB_WORDS):
        tags.add("DATABASE")
    if lowered.endswith(_CONFIG_SUFFIXES) or any(n in base for n in _CONFIG_NAMES):
        tags.add("CONFIGURATION")
    if any(w in lowered for w in _INFRA_WORDS) or base == "dockerfile":
        tags.add("INFRASTRUCTURE")
    if any(w in lowered for w in _INPUT_WORDS):
        tags.add("INPUT_HANDLING")
    if any(w in lowered for w in _OUTPUT_WORDS):
        tags.add("OUTPUT_HANDLING")
    if not tags:
        tags.add("CODE_BEHAVIOR" if state == "MODIFIED" else "UNKNOWN")
    return tags


def classify_symbol(symbol_id: str, path: str) -> set[str]:
    name = symbol_id.rsplit(":", 1)[-1].lower()
    tags: set[str] = set()
    if any(w in name for w in _AUTH_WORDS):
        tags.add("AUTHENTICATION")
    if any(w in name for w in _AUTHZ_WORDS):
        tags.add("AUTHORIZATION")
    if any(w in name for w in _CRYPTO_WORDS):
        tags.add("CRYPTO")
    if any(w in name for w in _SECRET_WORDS):
        tags.add("SECRET_HANDLING")
    if any(w in name for w in _DB_WORDS):
        tags.add("DATABASE")
    if any(w in name for w in _INPUT_WORDS):
        tags.add("INPUT_HANDLING")
    if any(w in name for w in _OUTPUT_WORDS):
        tags.add("OUTPUT_HANDLING")
    if not tags:
        tags.add("CODE_BEHAVIOR")
    return tags


def _regions(path: str, before: str, after: str, *, max_regions: int) -> tuple[list[ChangedRegion], bool]:
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    regions: list[ChangedRegion] = []
    for tag, _, _, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        regions.append(ChangedRegion(path=path, start_line=max(j1 + 1, 1), end_line=max(j2, j1 + 1), kind="MODIFIED"))
    capped = False
    if len(regions) > max_regions:
        capped = True
        regions = [ChangedRegion(path=path, start_line=1, end_line=max(len(after_lines), 1), kind="MODIFIED")]
    return regions, capped


def compare_snapshots(
    base: ComparisonSnapshot,
    target: ComparisonSnapshot,
    *,
    base_graph: Any = None,
    target_graph: Any = None,
    max_regions_per_file: int = 50,
) -> ChangeSet:
    if base.audit_id != target.audit_id:
        raise ChangeError(ChangeErrorCode.CROSS_AUDIT, "snapshots belong to different audits")
    if base.project_id and target.project_id and base.project_id != target.project_id:
        raise ChangeError(ChangeErrorCode.CROSS_PROJECT, "snapshots belong to different projects")
    if base.snapshot_id == target.snapshot_id:
        raise ChangeError(ChangeErrorCode.INVALID, "identical snapshot ids: nothing to compare")
    limitations: list[str] = []
    base_map = dict(base.files)
    target_map = dict(target.files)
    base_digests = {p: _digest(c) for p, c in base_map.items()}
    target_digests = {p: _digest(c) for p, c in target_map.items()}

    removed = sorted(set(base_map) - set(target_map))
    added = sorted(set(target_map) - set(base_map))
    # rename/move pairing by identical content digest (deterministic greedy)
    digest_to_removed: dict[str, list[str]] = {}
    for path in removed:
        digest_to_removed.setdefault(base_digests[path], []).append(path)
    digest_to_added: dict[str, list[str]] = {}
    for path in added:
        digest_to_added.setdefault(target_digests[path], []).append(path)
    renamed: dict[str, str] = {}
    for digest in sorted(set(digest_to_removed) & set(digest_to_added)):
        for old, new in zip(sorted(digest_to_removed[digest]), sorted(digest_to_added[digest])):
            renamed[old] = new
    for old, new in renamed.items():
        removed.remove(old)
        added.remove(new)

    files: list[ChangedFile] = []
    classifications: list[ChangeClassification] = []
    region_capped = False
    for path in sorted(set(base_map) & set(target_map)):
        if base_digests[path] == target_digests[path]:
            continue
        before, after = base_map[path], target_map[path]
        if _is_binary(before) or _is_binary(after):
            files.append(ChangedFile(path=path, state="UNKNOWN", generated=_is_generated(path)))
            limitations.append(f"uncomparable-binary:{path}")
            continue
        regions, capped = _regions(path, before, after, max_regions=max_regions_per_file)
        region_capped = region_capped or capped
        tags = classify_path(path, state="MODIFIED")
        files.append(ChangedFile(path=path, state="MODIFIED", generated=_is_generated(path), regions=tuple(regions), classifications=tuple(sorted(tags))))
        classifications.append(ChangeClassification(subject=path, subject_kind="file", classifications=tuple(sorted(tags)), reason="path-and-content-rules"))
    for path in added:
        content = target_map[path]
        if _is_binary(content):
            files.append(ChangedFile(path=path, state="UNKNOWN", generated=_is_generated(path)))
            limitations.append(f"uncomparable-binary:{path}")
            continue
        tags = classify_path(path, state="ADDED")
        files.append(ChangedFile(path=path, state="ADDED", generated=_is_generated(path), regions=(ChangedRegion(path=path, start_line=1, end_line=max(len(content.splitlines()), 1), kind="ADDED"),), classifications=tuple(sorted(tags))))
        classifications.append(ChangeClassification(subject=path, subject_kind="file", classifications=tuple(sorted(tags)), reason="path-rules"))
    for path in removed:
        tags = classify_path(path, state="REMOVED")
        files.append(ChangedFile(path=path, state="REMOVED", generated=_is_generated(path), classifications=tuple(sorted(tags))))
        classifications.append(ChangeClassification(subject=path, subject_kind="file", classifications=tuple(sorted(tags)), reason="path-rules"))
    for old, new in sorted(renamed.items()):
        old_dir, new_dir = old.rsplit("/", 1)[0] if "/" in old else "", new.rsplit("/", 1)[0] if "/" in new else ""
        state = "RENAMED" if old_dir == new_dir else "MOVED"
        tags = classify_path(new, state="MODIFIED")
        files.append(ChangedFile(path=new, previous_path=old, state=state, generated=_is_generated(new), classifications=tuple(sorted(tags))))
        classifications.append(ChangeClassification(subject=new, subject_kind="file", classifications=tuple(sorted(tags)), reason="rename-or-move-by-digest"))
    if region_capped:
        limitations.append("region-precision-capped: whole-file regions used")

    symbols = _link_symbols(files, base_graph=base_graph, target_graph=target_graph, limitations=limitations)
    for symbol in symbols:
        tags = classify_symbol(symbol.symbol_id, symbol.path)
        classifications.append(ChangeClassification(subject=symbol.symbol_id, subject_kind="symbol", classifications=tuple(sorted(tags)), reason="symbol-name-rules"))
    routes = _link_routes(symbols, files, base_graph=base_graph, target_graph=target_graph)
    dependencies = _link_dependencies(files, base_graph=base_graph, target_graph=target_graph, limitations=limitations)
    db_relations = _link_db_relations(base_graph=base_graph, target_graph=target_graph, limitations=limitations)

    coverage = "complete"
    if limitations:
        coverage = "partial"
    payload = {
        "audit": base.audit_id, "project": base.project_id or target.project_id,
        "base": [base.snapshot_id, base.revision], "target": [target.snapshot_id, target.revision],
        "files": [[f.path, f.previous_path, f.state, base_digests.get(f.previous_path or f.path, ""), target_digests.get(f.path, ""), [[r.start_line, r.end_line, r.kind] for r in f.regions], sorted(f.classifications)] for f in sorted(files, key=lambda x: x.path)],
        "symbols": [[s.symbol_id, s.change] for s in sorted(symbols, key=lambda x: x.symbol_id)],
        "routes": [[r.endpoint_id, r.change, r.auth_boundary_changed] for r in sorted(routes, key=lambda x: x.endpoint_id)],
        "dependencies": [[d.package, d.previous_version, d.current_version] for d in sorted(dependencies, key=lambda x: x.package)],
        "db": [[r.relation_id, r.change, r.database_object] for r in sorted(db_relations, key=lambda x: x.relation_id)],
    }
    return ChangeSet(
        audit_id=base.audit_id, project_id=base.project_id or target.project_id,
        base_snapshot_id=base.snapshot_id, target_snapshot_id=target.snapshot_id,
        base_revision=base.revision, target_revision=target.revision,
        source_provenance=f"{base.source_provenance} -> {target.source_provenance}".strip(" ->"),
        files=tuple(sorted(files, key=lambda x: x.path)), symbols=tuple(sorted(symbols, key=lambda x: x.symbol_id)),
        routes=tuple(sorted(routes, key=lambda x: x.endpoint_id)),
        dependencies=tuple(sorted(dependencies, key=lambda x: x.package)),
        database_relations=tuple(sorted(db_relations, key=lambda x: x.relation_id)),
        classifications=tuple(classifications), coverage=coverage, limitations=tuple(limitations),
        change_digest=canonical_digest(payload),
    )


def _link_symbols(files: list[ChangedFile], *, base_graph: Any, target_graph: Any, limitations: list[str]) -> list[ChangedSymbol]:
    if target_graph is None and base_graph is None:
        limitations.append("symbol-linking-unavailable: no code intelligence graphs")
        return []
    changed_paths = {f.path for f in files if f.state in ("ADDED", "MODIFIED")}
    removed_paths = {f.path for f in files if f.state == "REMOVED"}
    renamed_new = {f.path for f in files if f.state in ("RENAMED", "MOVED")}
    out: dict[str, ChangedSymbol] = {}
    if target_graph is not None:
        base_ids = {s for s in getattr(base_graph, "symbols", {})} if base_graph is not None else set()
        regions_by_path: dict[str, list[ChangedRegion]] = {}
        for f in files:
            regions_by_path.setdefault(f.path, []).extend(f.regions)
        for sid, symbol in sorted(getattr(target_graph, "symbols", {}).items()):
            if symbol.file not in changed_paths and symbol.file not in renamed_new:
                continue
            regions = regions_by_path.get(symbol.file, [])
            overlapped = any(r.start_line <= symbol.location.line <= r.end_line for r in regions) if regions else True
            if not overlapped:
                continue
            change = "ADDED" if sid not in base_ids else "MODIFIED"
            out[sid] = ChangedSymbol(symbol_id=sid, path=symbol.file, change=change)
    if base_graph is not None:
        target_ids = {s for s in getattr(target_graph, "symbols", {})} if target_graph is not None else set()
        for sid, symbol in sorted(getattr(base_graph, "symbols", {}).items()):
            if symbol.file in removed_paths and sid not in target_ids:
                out[sid] = ChangedSymbol(symbol_id=sid, path=symbol.file, change="REMOVED")
    return sorted(out.values(), key=lambda s: s.symbol_id)


def _link_routes(symbols: list[ChangedSymbol], files: list[ChangedFile], *, base_graph: Any, target_graph: Any) -> list[ChangedRoute]:
    if target_graph is None:
        return []
    changed_ids = {s.symbol_id for s in symbols}
    changed_paths = {f.path for f in files if f.state != "UNCHANGED"}
    base_endpoints = {e: ep for e, ep in getattr(base_graph, "endpoints", {}).items()} if base_graph is not None else {}
    out: list[ChangedRoute] = []
    for eid, endpoint in sorted(getattr(target_graph, "endpoints", {}).items()):
        handler_hit = endpoint.handler_id in changed_ids
        file_hit = any(endpoint.handler_id.startswith(p.rsplit(".", 1)[0] + ":") for p in changed_paths if "." in p) if endpoint.handler_id else False
        location_hit = endpoint.location.path in changed_paths
        if not (handler_hit or file_hit or location_hit):
            continue
        base_ep = base_endpoints.get(eid)
        change = "ADDED" if base_ep is None else "MODIFIED"
        boundary_changed = base_ep is not None and base_ep.auth_boundary_id != endpoint.auth_boundary_id
        out.append(ChangedRoute(endpoint_id=eid, change=change, auth_boundary_changed=boundary_changed))
    return out


def _link_dependencies(files: list[ChangedFile], *, base_graph: Any, target_graph: Any, limitations: list[str]) -> list[ChangedDependency]:
    if target_graph is None and base_graph is None:
        limitations.append("dependency-linking-unavailable: no code intelligence graphs")
        return []
    manifests = {f.path for f in files if _is_manifest(f.path) and f.state in ("ADDED", "MODIFIED", "REMOVED")}
    if not manifests:
        return []
    base_edges = {(e.package, e.importer): e for e in getattr(base_graph, "dep_edges", [])} if base_graph is not None else {}
    target_edges = {(e.package, e.importer): e for e in getattr(target_graph, "dep_edges", [])} if target_graph is not None else {}
    out: dict[str, ChangedDependency] = {}
    for (package, importer), edge in sorted(target_edges.items()):
        if edge.manifest_path not in manifests and importer not in manifests:
            continue
        base_edge = base_edges.get((package, importer))
        previous = base_edge.version if base_edge else ""
        if base_edge is None or base_edge.version != edge.version:
            out[f"{package}@{importer}"] = ChangedDependency(package=package, previous_version=previous, current_version=edge.version, manifest_path=edge.manifest_path or importer)
    return sorted(out.values(), key=lambda d: (d.package, d.manifest_path))


def _link_db_relations(*, base_graph: Any, target_graph: Any, limitations: list[str]) -> list[ChangedDatabaseRelation]:
    if target_graph is None and base_graph is None:
        return []
    base_rels = {r.relation_id: r for r in getattr(base_graph, "db_relations", [])} if base_graph is not None else {}
    target_rels = {r.relation_id: r for r in getattr(target_graph, "db_relations", [])} if target_graph is not None else {}
    out: list[ChangedDatabaseRelation] = []
    for rid in sorted(set(target_rels) - set(base_rels)):
        rel = target_rels[rid]
        out.append(ChangedDatabaseRelation(relation_id=rid, change="ADDED", database_object=rel.database_object))
    for rid in sorted(set(base_rels) - set(target_rels)):
        rel = base_rels[rid]
        out.append(ChangedDatabaseRelation(relation_id=rid, change="REMOVED", database_object=rel.database_object))
    return out
