"""Security knowledge service — POST-RC-011.

Facade that wires the store port, the allowlisted query port, the
memory policy, and the regression comparator. Integration with the
Change / Threat / Agent layers is CONTEXT ONLY: layer output may be
persisted as an observation record, but it never grants authority,
never raises trust, and never creates or transitions a Finding.

No delete API exists: retention is metadata, not an operation.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.security_knowledge.comparator import KnowledgeComparator
from emo_cyber_agent.security_knowledge.errors import KnowledgeError, KnowledgeErrorCode
from emo_cyber_agent.security_knowledge.provenance import build_knowledge_provenance, trace_chain
from emo_cyber_agent.security_knowledge.queries import ALLOWED_KNOWLEDGE_QUERIES, KnowledgeQueryPort
from emo_cyber_agent.security_knowledge.records import build_knowledge_record, record_reference
from emo_cyber_agent.security_knowledge.regression import (
    compare_regression,
    evaluate_precedence,
    evaluate_staleness,
)
from emo_cyber_agent.security_knowledge.scope import access_decision, check_record_scope
from emo_cyber_agent.security_knowledge.spec import (
    KnowledgeAccess,
    KnowledgeProvenance,
    KnowledgeRecord,
    KnowledgeReference,
    KnowledgeRetention,
    RegressionComparison,
    SecurityRegressionRecord,
)
from emo_cyber_agent.security_knowledge.store import InMemoryKnowledgeStore, SecurityKnowledgeStore

LAYER_SOURCE_TYPES: dict[str, str] = {
    "change-analysis": "change_analysis",
    "threat-model": "threat_model",
    "agent-security": "agent_security",
}

LAYER_CATEGORIES: dict[str, str] = {
    "change-analysis": "CHANGE_REGRESSION_SIGNAL",
    "threat-model": "THREAT_MODEL_OBSERVATION",
    "agent-security": "SECURITY_CONTROL_OBSERVATION",
}


class SecurityKnowledgeService:
    def __init__(
        self,
        store: SecurityKnowledgeStore | None = None,
        *,
        origin: str = "core:security-knowledge",
        collector: str = "",
    ) -> None:
        self._store = store if store is not None else InMemoryKnowledgeStore()
        self._queries = KnowledgeQueryPort(self._store)
        self._origin = origin
        self._collector = collector
        self.comparator = KnowledgeComparator()

    @property
    def store(self) -> SecurityKnowledgeStore:
        return self._store

    @property
    def allowed_queries(self) -> tuple[str, ...]:
        return ALLOWED_KNOWLEDGE_QUERIES

    @property
    def query_history(self) -> list[dict[str, Any]]:
        return list(self._queries.history)

    def access(self, *, audit_id: str, project_id: str, operations: tuple[str, ...] = ("read",)) -> KnowledgeAccess:
        return access_decision(audit_id=audit_id, project_id=project_id, operations=operations)

    def remember(
        self,
        *,
        audit_id: str,
        project_id: str,
        source_type: str,
        source_id: str,
        category: str,
        snapshot_id: str = "",
        scope_kind: str = "SNAPSHOT_BOUND",
        content: dict[str, Any] | None = None,
        created_from_evidence_ids: tuple[str, ...] = (),
        related_finding_id: str = "",
        verification_ref: str = "",
        regression_key: str = "",
        trust_level: str = "untrusted",
        provenance: KnowledgeProvenance | None = None,
        retention: KnowledgeRetention | None = None,
        origin: str = "",
        collector: str = "",
        parent_digests: tuple[str, ...] = (),
    ) -> tuple[KnowledgeRecord, bool]:
        """Atomic persist: validate → canonicalize → digest → scope →
        store. Returns (record, quarantined). Any violation raises and
        leaves no partial record behind."""
        check_forbidden_scope_tokens(audit_id, project_id, snapshot_id)
        if provenance is None:
            provenance = build_knowledge_provenance(
                origin=origin or self._origin,
                collector=collector or self._collector,
                evidence_ids=created_from_evidence_ids,
                parent_digests=parent_digests,
            )
        record, quarantined = build_knowledge_record(
            audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id,
            scope_kind=scope_kind, source_type=source_type, source_id=source_id,
            category=category, created_from_evidence_ids=created_from_evidence_ids,
            content=content, related_finding_id=related_finding_id,
            verification_ref=verification_ref, regression_key=regression_key,
            trust_level=trust_level, provenance=provenance, retention=retention,
        )
        check_record_scope(record, audit_id=audit_id, project_id=project_id)
        self._store.store_record(record)
        return record, quarantined

    def remember_from_layer(
        self,
        layer: str,
        *,
        audit_id: str,
        project_id: str,
        source_id: str,
        snapshot_id: str = "",
        content: dict[str, Any] | None = None,
        created_from_evidence_ids: tuple[str, ...] = (),
        regression_key: str = "",
        parent_digests: tuple[str, ...] = (),
    ) -> KnowledgeRecord:
        """Layer context path. Category is derived from the layer and
        trust is pinned to 'untrusted': historical layer output is
        context, never authority."""
        if layer not in LAYER_SOURCE_TYPES:
            raise KnowledgeError(KnowledgeErrorCode.INVALID, f"unknown context layer: {layer[:80]}")
        record, _ = self.remember(
            audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id,
            source_type=LAYER_SOURCE_TYPES[layer], source_id=source_id,
            category=LAYER_CATEGORIES[layer], content=content,
            created_from_evidence_ids=created_from_evidence_ids,
            regression_key=regression_key, trust_level="untrusted",
            origin=f"layer:{layer}", parent_digests=parent_digests,
        )
        return record

    def remember_regression(
        self,
        *,
        audit_id: str,
        project_id: str,
        regression_key: str,
        base_snapshot_id: str = "",
        target_snapshot_id: str = "",
        before_digest: str = "",
        after_digest: str = "",
        before_present: bool = True,
        after_present: bool = True,
        comparable: bool = True,
        coverage: str = "complete",
        prior_digests: tuple[str, ...] = (),
        evidence_ids: tuple[str, ...] = (),
    ) -> tuple[SecurityRegressionRecord, KnowledgeRecord]:
        """Compare, then persist both the regression record (as a
        CHANGE_REGRESSION_SIGNAL knowledge record) atomically."""
        regression = compare_regression(
            audit_id=audit_id, project_id=project_id, regression_key=regression_key,
            base_snapshot_id=base_snapshot_id, target_snapshot_id=target_snapshot_id,
            before_digest=before_digest, after_digest=after_digest,
            before_present=before_present, after_present=after_present,
            comparable=comparable, coverage=coverage, prior_digests=prior_digests,
            evidence_ids=evidence_ids,
            provenance=build_knowledge_provenance(
                origin=self._origin, collector=self._collector,
                evidence_ids=evidence_ids, parent_digests=(before_digest, after_digest),
            ),
        )
        record, _ = self.remember(
            audit_id=audit_id, project_id=project_id, snapshot_id=target_snapshot_id,
            scope_kind="RANGE_BOUND", source_type="change_analysis",
            source_id=regression.regression_id, category="CHANGE_REGRESSION_SIGNAL",
            content={
                "regression_id": regression.regression_id,
                "regression_key": regression.regression_key,
                "state": regression.state,
                "base_snapshot_id": regression.base_snapshot_id,
                "target_snapshot_id": regression.target_snapshot_id,
                "before_digest": regression.before_digest,
                "after_digest": regression.after_digest,
            },
            created_from_evidence_ids=tuple(evidence_ids),
            regression_key=regression_key,
        )
        return regression, record

    def get_record(self, record_id: str, *, audit_id: str, project_id: str, snapshot_id: str = "") -> KnowledgeRecord | None:
        record, _ = self._queries.get_record(record_id, audit_id=audit_id, project_id=project_id)
        if record is None:
            return None
        check_record_scope(record, audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id)
        return record

    def find_by_regression_key(self, regression_key: str, *, audit_id: str, project_id: str) -> list[KnowledgeRecord]:
        records, _ = self._queries.find_by_regression_key(regression_key, audit_id=audit_id, project_id=project_id)
        return records

    def find_related_observations(self, object_id: str, *, audit_id: str, project_id: str) -> list[KnowledgeRecord]:
        records, _ = self._queries.find_related_observations(object_id, audit_id=audit_id, project_id=project_id)
        return records

    def list_project_regressions(self, *, audit_id: str, project_id: str) -> list[KnowledgeRecord]:
        records, _ = self._queries.list_project_regressions(audit_id=audit_id, project_id=project_id)
        return records

    def get_prior_verification(self, context: str, *, audit_id: str, project_id: str) -> list[KnowledgeRecord]:
        records, _ = self._queries.get_prior_verification(context, audit_id=audit_id, project_id=project_id)
        return records

    def compare_with_baseline(
        self,
        regression_key: str,
        *,
        audit_id: str,
        project_id: str,
        baseline_snapshot_id: str = "",
        target_snapshot_id: str = "",
        comparable: bool = True,
        coverage: str = "complete",
    ) -> RegressionComparison:
        records, _ = self._queries.compare_with_baseline(
            regression_key, audit_id=audit_id, project_id=project_id,
            baseline_snapshot_id=baseline_snapshot_id,
        )
        baseline = _pick_snapshot(records, baseline_snapshot_id)
        target = _pick_snapshot(records, target_snapshot_id)
        evidence = tuple(sorted({eid for r in (baseline, target) if r is not None for eid in r.created_from_evidence_ids}))
        return self.comparator.compare(
            baseline.content if baseline else None,
            target.content if target else None,
            comparable=comparable, coverage=coverage, evidence_ids=evidence,
        )

    def precedence(self, historical: KnowledgeRecord, current: KnowledgeRecord) -> str:
        """Current evidence outranks history; history is labeled, kept."""
        check_record_scope(historical, audit_id=current.audit_id, project_id=current.project_id)
        return evaluate_precedence(
            historical_digest=historical.content_digest,
            current_digest=current.content_digest,
            historical_snapshot_id=historical.snapshot_id,
            current_snapshot_id=current.snapshot_id,
        )

    def staleness(self, record: KnowledgeRecord, *, current_snapshot_id: str = "", versions: dict[str, str] | None = None) -> str:
        return evaluate_staleness(
            record_snapshot_id=record.snapshot_id,
            record_schema_version=record.schema_version,
            current_snapshot_id=current_snapshot_id,
            versions=versions,
        )

    def reference(self, record: KnowledgeRecord) -> KnowledgeReference:
        return record_reference(record)

    def provenance_chain(self, record: KnowledgeRecord) -> list[str]:
        return trace_chain(record)

    def run_named(self, query_type: str, **kwargs: Any) -> tuple[Any, dict[str, Any]]:
        return self._queries.run_named(query_type, **kwargs)


def _pick_snapshot(records: list[KnowledgeRecord], snapshot_id: str) -> KnowledgeRecord | None:
    if not snapshot_id:
        return records[0] if records else None
    for record in records:
        if record.snapshot_id == snapshot_id:
            return record
    return None


def check_forbidden_scope_tokens(*markers: str) -> None:
    forbidden = ("other_audit_id", "raw_backend_query", "path_escape", "tenant_scope", "policy_override")
    for marker in markers:
        lowered = str(marker).lower()
        for token in forbidden:
            if token in lowered:
                raise KnowledgeError(KnowledgeErrorCode.QUERY_REJECTED, f"forbidden scope marker: {token}")
