"""Graph query port — POST-RC-005.

Fixed, allowlisted query surface. No raw provider query language
reaches Core or execution. Every query records provenance for
re-investigation. Inputs are validated (paths, ids, bounds); hostile
input raises QUERY_REJECTED, never executes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from emo_cyber_agent.code_intelligence.errors import CodeIntelligenceError, CodeIntelligenceErrorCode
from emo_cyber_agent.code_intelligence.graph import CodeGraph
from emo_cyber_agent.code_intelligence.spec import QueryProvenance, normalize_code_path

ALLOWED_QUERY_TYPES: tuple[str, ...] = (
    "find_symbol",
    "find_definitions",
    "find_references",
    "find_callers",
    "find_callees",
    "find_imports",
    "find_exports",
    "find_paths",
    "find_sources_for_sink",
    "find_sinks_for_source",
    "find_reachable_paths",
    "endpoint_dependencies",
    "authorization_paths",
    "database_relationships",
    "dependency_paths",
)

_MAX_TARGET_LEN = 320


def _clean_target(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        raise CodeIntelligenceError(CodeIntelligenceErrorCode.QUERY_REJECTED, "empty query target")
    t = target.strip()
    if len(t) > _MAX_TARGET_LEN:
        raise CodeIntelligenceError(CodeIntelligenceErrorCode.QUERY_REJECTED, "query target too long")
    if "\x00" in t or "\n" in t or "\r" in t:
        raise CodeIntelligenceError(CodeIntelligenceErrorCode.QUERY_REJECTED, "query target carries control characters")
    return t


def _digest(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


class CodeGraphQueryPort:
    """Safe queries over one snapshot-scoped graph. Read-only."""

    def __init__(self, graph: CodeGraph):
        self._graph = graph
        self.history: list[QueryProvenance] = []

    @property
    def allowed_queries(self) -> tuple[str, ...]:
        return ALLOWED_QUERY_TYPES

    def _record(self, query_type: str, target: str, result: Any) -> QueryProvenance:
        prov = QueryProvenance(
            query_type=query_type, target=target, provider=self._graph.snapshot.provider,
            provider_version=self._graph.snapshot.provider_version,
            snapshot_digest=self._graph.snapshot.source_digest,
            timestamp=datetime.now(timezone.utc).isoformat(), result_digest=_digest(result),
        )
        self.history.append(prov)
        return prov

    def _scope(self, audit_id: str) -> None:
        if audit_id != self._graph.snapshot.project.audit_id:
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.OUT_OF_SCOPE, "query audit_id does not match graph snapshot")

    def find_symbol(self, name: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        target = _clean_target(name).lower()
        hits = [s.model_dump(mode="json") for sid, s in sorted(self._graph.symbols.items()) if target in s.name.lower() or target == sid.lower()]
        return hits, self._record("find_symbol", target, [h.get("symbol_id") for h in hits])

    def find_definitions(self, symbol_id: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        target = _clean_target(symbol_id)
        hits = [s.model_dump(mode="json") for sid, s in sorted(self._graph.symbols.items()) if sid == target]
        return hits, self._record("find_definitions", target, [h.get("symbol_id") for h in hits])

    def find_references(self, symbol_id: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        target = _clean_target(symbol_id)
        refs = [r.model_dump(mode="json") for nid, r in sorted(self._graph.ast_refs.items()) if r.symbol_id == target]
        callers = self._graph.callers(target, audit_id=audit_id)
        return refs, self._record("find_references", target, {"refs": len(refs), "callers": callers})

    def find_callers(self, symbol_id: str, *, audit_id: str, max_depth: int = 3) -> tuple[list[str], QueryProvenance]:
        self._scope(audit_id)
        result = self._graph.callers(_clean_target(symbol_id), audit_id=audit_id, max_depth=max(1, min(max_depth, 10)))
        return result, self._record("find_callers", symbol_id, result)

    def find_callees(self, symbol_id: str, *, audit_id: str, max_depth: int = 3) -> tuple[list[str], QueryProvenance]:
        self._scope(audit_id)
        result = self._graph.callees(_clean_target(symbol_id), audit_id=audit_id, max_depth=max(1, min(max_depth, 10)))
        return result, self._record("find_callees", symbol_id, result)

    def find_imports(self, path: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        clean = normalize_code_path(_clean_target(path))
        hits = [e.model_dump(mode="json") for e in self._graph.dep_edges if e.importer == clean or e.importer.startswith(clean.rstrip("/") + "/")]
        return hits, self._record("find_imports", clean, [h.get("package") for h in hits])

    def find_exports(self, path: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        clean = normalize_code_path(_clean_target(path))
        hits = [s.model_dump(mode="json") for sid, s in sorted(self._graph.symbols.items()) if s.file == clean and s.exported]
        return hits, self._record("find_exports", clean, [h.get("symbol_id") for h in hits])

    def find_paths(self, source_id: str, sink_id: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        src, snk = _clean_target(source_id), _clean_target(sink_id)
        hits = [p.model_dump(mode="json") for pid, p in sorted(self._graph.taint_paths.items()) if p.source_id == src and p.sink_id == snk]
        return hits, self._record("find_paths", f"{src}->{snk}", [h.get("path_id") for h in hits])

    def find_sources_for_sink(self, sink_id: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        target = _clean_target(sink_id)
        sources = sorted({p.source_id for p in self._graph.taint_paths.values() if p.sink_id == target})
        return [{"source_id": s} for s in sources], self._record("find_sources_for_sink", target, sources)

    def find_sinks_for_source(self, source_id: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        target = _clean_target(source_id)
        sinks = sorted({p.sink_id for p in self._graph.taint_paths.values() if p.source_id == target})
        return [{"sink_id": s} for s in sinks], self._record("find_sinks_for_source", target, sinks)

    def find_reachable_paths(self, component_id: str, *, audit_id: str) -> tuple[list[str], QueryProvenance]:
        self._scope(audit_id)
        result = self._graph.dataflow_successors(_clean_target(component_id), audit_id=audit_id)
        return result, self._record("find_reachable_paths", component_id, result)

    def endpoint_dependencies(self, endpoint_id: str, *, audit_id: str) -> tuple[dict[str, Any], QueryProvenance]:
        self._scope(audit_id)
        target = _clean_target(endpoint_id)
        try:
            ep = self._graph.endpoints[target]
        except KeyError:
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.QUERY_REJECTED, f"unknown endpoint: {target[:80]}") from None
        result = {"endpoint_id": target, "handler_id": ep.handler_id, "downstream": list(ep.downstream), "auth_boundary_id": ep.auth_boundary_id}
        return result, self._record("endpoint_dependencies", target, result)

    def authorization_paths(self, endpoint_id: str, *, audit_id: str) -> tuple[dict[str, Any], QueryProvenance]:
        self._scope(audit_id)
        target = _clean_target(endpoint_id)
        try:
            ep = self._graph.endpoints[target]
        except KeyError:
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.QUERY_REJECTED, f"unknown endpoint: {target[:80]}") from None
        boundary = self._graph.boundaries.get(ep.auth_boundary_id)
        result: dict[str, Any] = {"endpoint_id": target, "boundary_present": boundary is not None}
        if boundary is not None:
            result["boundary"] = boundary.model_dump(mode="json")
        return result, self._record("authorization_paths", target, result)

    def database_relationships(self, code_id: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        target = _clean_target(code_id)
        hits = [r.model_dump(mode="json") for r in self._graph.db_relations if r.code_id == target]
        return hits, self._record("database_relationships", target, [h.get("relation_id") for h in hits])

    def dependency_paths(self, package: str, *, audit_id: str) -> tuple[list[dict[str, Any]], QueryProvenance]:
        self._scope(audit_id)
        target = _clean_target(package).lower()
        hits = [e.model_dump(mode="json") for e in self._graph.dep_edges if e.package.lower() == target]
        return hits, self._record("dependency_paths", target, [h.get("importer") for h in hits])
