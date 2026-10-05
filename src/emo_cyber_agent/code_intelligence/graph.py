"""Snapshot-scoped code graph — POST-RC-005.

In-memory normalized graph. Bound to exactly one (audit_id, project,
snapshot). No external graph database. Every mutation enforces size
limits; over-limit ingestion raises GRAPH_LIMIT_REACHED (the service
converts it to PARTIAL/LIMIT_REACHED metadata — never silent
truncation). Traversals are depth- and result-capped.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from pydantic import BaseModel, ConfigDict

from emo_cyber_agent.code_intelligence.errors import CodeIntelligenceError, CodeIntelligenceErrorCode
from emo_cyber_agent.code_intelligence.spec import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_PATH_LENGTH,
    DEFAULT_MAX_RESULTS,
    DEFAULT_MAX_TRAVERSAL_DEPTH,
    AstNodeReference,
    AuthorizationBoundary,
    CallEdge,
    CodeComponent,
    CodeFile,
    CodeSnapshot,
    CodeSymbol,
    ControlFlowEdge,
    DatabaseRelationship,
    DataFlowEdge,
    DataSink,
    DataSource,
    DependencyEdge,
    ResultQuality,
    RouteEndpoint,
    TaintPath,
)


class GraphLimits(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    max_nodes: int = DEFAULT_MAX_NODES
    max_edges: int = DEFAULT_MAX_EDGES
    max_traversal_depth: int = DEFAULT_MAX_TRAVERSAL_DEPTH
    max_results: int = DEFAULT_MAX_RESULTS
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH


class CodeGraph:
    """One graph per (audit, project, snapshot). Not shared, not global."""

    def __init__(self, snapshot: CodeSnapshot, *, limits: GraphLimits | None = None):
        self._snapshot = snapshot
        self._limits = limits or GraphLimits()
        self._truncated = False
        self.files: dict[str, CodeFile] = {}
        self.symbols: dict[str, CodeSymbol] = {}
        self.ast_refs: dict[str, AstNodeReference] = {}
        self.call_edges: list[CallEdge] = []
        self.cf_edges: list[ControlFlowEdge] = []
        self.df_edges: list[DataFlowEdge] = []
        self.dep_edges: list[DependencyEdge] = []
        self.endpoints: dict[str, RouteEndpoint] = {}
        self.boundaries: dict[str, AuthorizationBoundary] = {}
        self.sources: dict[str, DataSource] = {}
        self.sinks: dict[str, DataSink] = {}
        self.taint_paths: dict[str, TaintPath] = {}
        self.components: dict[str, CodeComponent] = {}
        self.db_relations: list[DatabaseRelationship] = []

    @property
    def snapshot(self) -> CodeSnapshot:
        return self._snapshot

    @property
    def limits(self) -> GraphLimits:
        return self._limits

    @property
    def truncated(self) -> bool:
        return self._truncated

    @property
    def quality(self) -> ResultQuality:
        return ResultQuality.PARTIAL if self._truncated else ResultQuality.COMPLETE

    # -- guarded mutation -------------------------------------------------

    def _check_node_budget(self, count: int = 1) -> None:
        if self.node_count() + count > self._limits.max_nodes:
            self._truncated = True
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.GRAPH_LIMIT_REACHED, f"node budget exceeded (max_nodes={self._limits.max_nodes})")

    def _check_edge_budget(self, count: int = 1) -> None:
        if self.edge_count() + count > self._limits.max_edges:
            self._truncated = True
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.GRAPH_LIMIT_REACHED, f"edge budget exceeded (max_edges={self._limits.max_edges})")

    def node_count(self) -> int:
        return len(self.files) + len(self.symbols) + len(self.ast_refs) + len(self.endpoints) + len(self.boundaries) + len(self.sources) + len(self.sinks) + len(self.components)

    def edge_count(self) -> int:
        return len(self.call_edges) + len(self.cf_edges) + len(self.df_edges) + len(self.dep_edges) + len(self.db_relations)

    def add_file(self, f: CodeFile) -> None:
        if f.path not in self.files:
            self._check_node_budget()
        self.files[f.path] = f

    def add_symbol(self, s: CodeSymbol) -> None:
        if s.symbol_id not in self.symbols:
            self._check_node_budget()
        self.symbols[s.symbol_id] = s

    def add_ast_ref(self, r: AstNodeReference) -> None:
        if r.node_id not in self.ast_refs:
            self._check_node_budget()
        self.ast_refs[r.node_id] = r

    def add_call_edge(self, e: CallEdge) -> None:
        self._check_edge_budget()
        self.call_edges.append(e)

    def add_cf_edge(self, e: ControlFlowEdge) -> None:
        self._check_edge_budget()
        self.cf_edges.append(e)

    def add_df_edge(self, e: DataFlowEdge) -> None:
        self._check_edge_budget()
        self.df_edges.append(e)

    def add_dep_edge(self, e: DependencyEdge) -> None:
        self._check_edge_budget()
        self.dep_edges.append(e)

    def add_endpoint(self, e: RouteEndpoint) -> None:
        if e.endpoint_id not in self.endpoints:
            self._check_node_budget()
        self.endpoints[e.endpoint_id] = e

    def add_boundary(self, b: AuthorizationBoundary) -> None:
        if b.boundary_id not in self.boundaries:
            self._check_node_budget()
        self.boundaries[b.boundary_id] = b

    def add_source(self, s: DataSource) -> None:
        if s.source_id not in self.sources:
            self._check_node_budget()
        self.sources[s.source_id] = s

    def add_sink(self, s: DataSink) -> None:
        if s.sink_id not in self.sinks:
            self._check_node_budget()
        self.sinks[s.sink_id] = s

    def add_taint_path(self, p: TaintPath) -> None:
        if len(p.node_ids) > self._limits.max_path_length:
            self._truncated = True
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.GRAPH_LIMIT_REACHED, f"taint path too long (max_path_length={self._limits.max_path_length})")
        self.taint_paths[p.path_id] = p

    def add_component(self, c: CodeComponent) -> None:
        if c.component_id not in self.components:
            self._check_node_budget()
        self.components[c.component_id] = c

    def add_db_relation(self, r: DatabaseRelationship) -> None:
        self._check_edge_budget()
        self.db_relations.append(r)

    # -- audit-scoped lookups ----------------------------------------------

    def _scope_ok(self, audit_id: str) -> bool:
        return audit_id == self._snapshot.project.audit_id

    def _require_scope(self, audit_id: str) -> None:
        if not self._scope_ok(audit_id):
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.OUT_OF_SCOPE, "graph is bound to a different audit_id")

    # -- traversals (depth- and result-capped) ------------------------------

    def callers(self, symbol_id: str, *, audit_id: str, max_depth: int = 3) -> list[str]:
        self._require_scope(audit_id)
        depth = min(max_depth, self._limits.max_traversal_depth)
        seen: list[str] = []
        frontier = deque([(symbol_id, 0)])
        visited = {symbol_id}
        while frontier and len(seen) < self._limits.max_results:
            current, dist = frontier.popleft()
            if dist >= depth:
                continue
            for edge in self.call_edges:
                if edge.callee_id == current and edge.caller_id not in visited:
                    visited.add(edge.caller_id)
                    seen.append(edge.caller_id)
                    frontier.append((edge.caller_id, dist + 1))
                    if len(seen) >= self._limits.max_results:
                        break
        return seen

    def callees(self, symbol_id: str, *, audit_id: str, max_depth: int = 3) -> list[str]:
        self._require_scope(audit_id)
        depth = min(max_depth, self._limits.max_traversal_depth)
        seen: list[str] = []
        frontier = deque([(symbol_id, 0)])
        visited = {symbol_id}
        while frontier and len(seen) < self._limits.max_results:
            current, dist = frontier.popleft()
            if dist >= depth:
                continue
            for edge in self.call_edges:
                if edge.caller_id == current and edge.callee_id not in visited:
                    visited.add(edge.callee_id)
                    seen.append(edge.callee_id)
                    frontier.append((edge.callee_id, dist + 1))
                    if len(seen) >= self._limits.max_results:
                        break
        return seen

    def dataflow_successors(self, node_id: str, *, audit_id: str, max_depth: int = 5) -> list[str]:
        self._require_scope(audit_id)
        depth = min(max_depth, self._limits.max_traversal_depth)
        seen: list[str] = []
        frontier = deque([(node_id, 0)])
        visited = {node_id}
        while frontier and len(seen) < self._limits.max_results:
            current, dist = frontier.popleft()
            if dist >= depth:
                continue
            for edge in self.df_edges:
                if edge.from_id == current and edge.to_id not in visited:
                    visited.add(edge.to_id)
                    seen.append(edge.to_id)
                    frontier.append((edge.to_id, dist + 1))
                    if len(seen) >= self._limits.max_results:
                        break
        return seen

    def summary(self) -> dict[str, Any]:
        return {
            "audit_id": self._snapshot.project.audit_id,
            "provider": self._snapshot.provider,
            "provider_version": self._snapshot.provider_version,
            "files": len(self.files),
            "symbols": len(self.symbols),
            "call_edges": len(self.call_edges),
            "dataflow_edges": len(self.df_edges),
            "endpoints": len(self.endpoints),
            "taint_paths": len(self.taint_paths),
            "quality": self.quality.value,
            "truncated": self._truncated,
        }
