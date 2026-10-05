"""Code intelligence service — POST-RC-005.

Core-owned orchestration: snapshot → provider.analyze → graph build →
evidence + observations. This is the ONLY allowed path from provider
output to security-relevant records. Hosts and adapters MUST NOT
interpret provider output directly.
"""

from __future__ import annotations

import json
from typing import Any

from emo_cyber_agent.code_intelligence.errors import CodeIntelligenceError, CodeIntelligenceErrorCode
from emo_cyber_agent.code_intelligence.graph import CodeGraph, GraphLimits
from emo_cyber_agent.code_intelligence.provider import CodeIntelligenceProvider
from emo_cyber_agent.code_intelligence.spec import (
    CODE_INTELLIGENCE_CONTRACT_VERSION,
    CodeFile,
    CodeObservation,
    CodeProject,
    CodeSnapshot,
    ObservationKind,
    content_digest,
    detect_language,
    normalize_code_path,
)


def snapshot_digest(files: dict[str, str]) -> str:
    canonical = json.dumps({k: content_digest(v) for k, v in sorted(files.items())}, sort_keys=True)
    return content_digest(canonical)


class CodeIntelligenceService:
    def __init__(self, provider: CodeIntelligenceProvider, *, limits: GraphLimits | None = None):
        self._provider = provider
        self._limits = limits or GraphLimits()

    @property
    def provider(self) -> CodeIntelligenceProvider:
        return self._provider

    def create_snapshot(self, project: CodeProject, files: dict[str, str], *, revision: str | None = None) -> CodeSnapshot:
        clean = {normalize_code_path(p): c for p, c in files.items()}
        return CodeSnapshot(project=project, provider=self._provider.provider_id, provider_version=self._provider.provider_version, revision=revision, source_digest=snapshot_digest(clean))

    def check_fresh(self, snapshot: CodeSnapshot, *, current_revision: str | None) -> None:
        if snapshot.revision and current_revision and snapshot.revision != current_revision:
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.STALE_SNAPSHOT, f"snapshot revision {snapshot.revision} != current {current_revision}")

    def analyze(self, snapshot: CodeSnapshot, files: dict[str, str]) -> CodeGraph:
        if snapshot.provider != self._provider.provider_id or snapshot.provider_version != self._provider.provider_version:
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.SNAPSHOT_INVALID, "snapshot bound to a different provider/version")
        clean = {normalize_code_path(p): c for p, c in files.items()}
        if snapshot_digest(clean) != snapshot.source_digest:
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.SNAPSHOT_INVALID, "files do not match snapshot digest")
        try:
            bundle = self._provider.analyze(snapshot=snapshot, files=clean)
        except CodeIntelligenceError:
            raise
        except Exception as e:
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.PROVIDER_ERROR, f"provider failed: {e}") from e
        graph = CodeGraph(snapshot, limits=self._limits)
        try:
            self._ingest(graph, clean, bundle)
        except CodeIntelligenceError as e:
            if e.code == CodeIntelligenceErrorCode.GRAPH_LIMIT_REACHED:
                return graph  # partial graph with truncated metadata — never silent
            raise
        return graph

    def _ingest(self, graph: CodeGraph, files: dict[str, str], bundle: Any) -> None:
        get = (lambda k, d=None: bundle.get(k, d)) if isinstance(bundle, dict) else (lambda k, d=None: getattr(bundle, k, d))
        skipped = set(get("skipped", []) or [])
        for path, content in files.items():
            if path in skipped:
                continue  # provider did not analyze it: no file node, no silent partial facts
            graph.add_file(CodeFile(path=path, language=detect_language(path), digest=content_digest(content), size_bytes=len(content.encode("utf-8", errors="replace"))))
        for item in get("symbols", []) or []:
            graph.add_symbol(item if hasattr(item, "symbol_id") else self._coerce("symbol", item))
        for item in get("ast_refs", []) or []:
            graph.add_ast_ref(item if hasattr(item, "node_id") else self._coerce("ast_ref", item))
        for item in get("call_edges", []) or []:
            graph.add_call_edge(item if hasattr(item, "caller_id") else self._coerce("call_edge", item))
        for item in get("dataflow_edges", []) or []:
            graph.add_df_edge(item if hasattr(item, "from_id") else self._coerce("df_edge", item))
        for item in get("dependency_edges", []) or []:
            graph.add_dep_edge(item if hasattr(item, "importer") else self._coerce("dep_edge", item))
        for item in get("endpoints", []) or []:
            graph.add_endpoint(item if hasattr(item, "endpoint_id") else self._coerce("endpoint", item))
        for item in get("boundaries", []) or []:
            graph.add_boundary(item if hasattr(item, "boundary_id") else self._coerce("boundary", item))
        for item in get("sources", []) or []:
            graph.add_source(item if hasattr(item, "source_id") else self._coerce("source", item))
        for item in get("sinks", []) or []:
            graph.add_sink(item if hasattr(item, "sink_id") else self._coerce("sink", item))
        for item in get("taint_paths", []) or []:
            graph.add_taint_path(item if hasattr(item, "path_id") else self._coerce("taint_path", item))
        for item in get("db_relations", []) or []:
            graph.add_db_relation(item if hasattr(item, "relation_id") else self._coerce("db_relation", item))
        for item in get("components", []) or []:
            graph.add_component(item if hasattr(item, "component_id") else self._coerce("component", item))

    def _coerce(self, kind: str, item: dict[str, Any]) -> Any:
        from emo_cyber_agent.code_intelligence.spec import (
            AstNodeReference,
            AuthorizationBoundary,
            CallEdge,
            CodeComponent,
            CodeSymbol,
            DatabaseRelationship,
            DataFlowEdge,
            DataSink,
            DataSource,
            DependencyEdge,
            RouteEndpoint,
            TaintPath,
        )

        table = {"symbol": CodeSymbol, "ast_ref": AstNodeReference, "call_edge": CallEdge, "df_edge": DataFlowEdge, "dep_edge": DependencyEdge, "endpoint": RouteEndpoint, "boundary": AuthorizationBoundary, "source": DataSource, "sink": DataSink, "taint_path": TaintPath, "db_relation": DatabaseRelationship, "component": CodeComponent}
        try:
            return table[kind](**item)
        except Exception as e:
            raise CodeIntelligenceError(CodeIntelligenceErrorCode.PROVIDER_ERROR, f"provider emitted malformed {kind}: {e}") from e

    # -- evidence + observations -------------------------------------------

    def build_evidence(self, graph: CodeGraph, *, query_type: str, target: str = "", result_digest: str = "") -> Any:
        """One EvidenceItem per call, fully provenanced. Raw graph dumps never stored."""
        from emo_cyber_agent.core.repository import redact_credentials
        from emo_cyber_agent.domain.models import EvidenceItem

        summary = redact_credentials(f"code-intel {query_type} target={target or 'graph'} files={len(graph.files)} symbols={len(graph.symbols)} quality={graph.quality.value} digest={result_digest[:16]}")[:500]
        return EvidenceItem(
            source_tool=f"code-intel:{graph.snapshot.provider}", source_version=graph.snapshot.provider_version,
            target_asset_id=graph.snapshot.project.asset_id or None, location=f"snapshot:{graph.snapshot.source_digest[:16]}",
            content_hash=result_digest or None, content_summary=summary,
            provenance={"provider": graph.snapshot.provider, "provider_version": graph.snapshot.provider_version, "snapshot_digest": graph.snapshot.source_digest, "audit_id": graph.snapshot.project.audit_id, "query_type": query_type, "target": target, "coverage": graph.quality.value, "contract_version": CODE_INTELLIGENCE_CONTRACT_VERSION},
        )

    def derive_observations(self, graph: CodeGraph, evidence_id: str) -> list[CodeObservation]:
        """Facts with evidence linkage. Kinds only — no severity, no verdicts."""
        observations: list[CodeObservation] = []
        for pid, path in sorted(graph.taint_paths.items()):
            observations.append(CodeObservation(observation_id=f"obs-taint-{pid}", kind=ObservationKind.DATAFLOW_PATH_FOUND, statement=f"TAINT_PATH_FOUND {path.source_id} -> {path.sink_id} ({len(path.node_ids)} nodes, completeness={path.completeness.value})", evidence_ids=(evidence_id,), provenance={"provider": graph.snapshot.provider}))
        for eid, ep in sorted(graph.endpoints.items()):
            observations.append(CodeObservation(observation_id=f"obs-route-{eid}", kind=ObservationKind.ROUTE_HANDLER_DISCOVERED, statement=f"ROUTE_HANDLER_DISCOVERED {ep.method} {ep.path} -> {ep.handler_id or 'unknown-handler'}", evidence_ids=(evidence_id,), location=ep.location, provenance={"provider": graph.snapshot.provider}))
            if ep.state_changing:
                observations.append(CodeObservation(observation_id=f"obs-state-{eid}", kind=ObservationKind.STATE_CHANGE_OPERATION, statement=f"STATE_CHANGE_OPERATION {ep.method} {ep.path}", evidence_ids=(evidence_id,), location=ep.location, provenance={"provider": graph.snapshot.provider}))
            if not ep.auth_boundary_id or ep.auth_boundary_id not in graph.boundaries:
                observations.append(CodeObservation(observation_id=f"obs-auth-{eid}", kind=ObservationKind.UNRESOLVED_AUTH_BOUNDARY, statement=f"UNRESOLVED_AUTH_BOUNDARY {ep.method} {ep.path}: no recorded authorization check", evidence_ids=(evidence_id,), location=ep.location, provenance={"provider": graph.snapshot.provider}))
        for rel in sorted(graph.db_relations, key=lambda r: r.relation_id):
            observations.append(CodeObservation(observation_id=f"obs-db-{rel.relation_id}", kind=ObservationKind.DATABASE_ACCESS_PATH, statement=f"DATABASE_ACCESS_PATH {rel.code_id} -> {rel.database_object} ({rel.kind})", evidence_ids=(evidence_id,), location=rel.location, provenance={"provider": graph.snapshot.provider}))
        for edge in sorted(graph.dep_edges, key=lambda e: (e.package, e.importer)):
            observations.append(CodeObservation(observation_id=f"obs-dep-{edge.package}-{content_digest(edge.importer)[:8]}", kind=ObservationKind.DEPENDENCY_USAGE, statement=f"DEPENDENCY_USAGE {edge.importer} imports {edge.package}@{edge.version or 'unknown'}", evidence_ids=(evidence_id,), provenance={"provider": graph.snapshot.provider}))
        return observations


def get_code_intelligence_tool_specs() -> list[Any]:
    """ToolSpecs for external analyzer providers (Joern/CodeQL/…). Flow:
    ToolRegistry → Policy → ToolExecutor → Provider Adapter → normalized
    intelligence → Evidence. No bypass."""
    from emo_cyber_agent.core.tool_registry import ToolSpec

    base = dict(version="1.0.0", description="Read-only code intelligence operation", category="other", risk_level="low", supports_read_only=True, supports_verification=False, supports_remediation=False, target_types=("repo",), evidence_behavior="summarize", timeout_ms=120000, tags=("code-intelligence",))
    return [
        ToolSpec(tool_id="code-intel.analyze", name="Code Intelligence Analyze", capabilities_required=("code.symbols.read",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="code-intel.query", name="Code Intelligence Query", capabilities_required=("code.symbols.read",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="code-intel.dataflow", name="Code Intelligence Dataflow", capabilities_required=("code.dataflow.read",), **base),  # type: ignore[arg-type]
    ]
