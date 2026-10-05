"""Allowlisted knowledge retrieval — POST-RC-011.

Every query binds to the caller's (audit, project) scope; any
requested identity outside it is DENY. No arbitrary SQL/DSL/
filter language exists. The caller cannot change enforced scope.
"""

from __future__ import annotations

from datetime import UTC
from typing import Any

from emo_cyber_agent.security_knowledge.errors import KnowledgeError, KnowledgeErrorCode
from emo_cyber_agent.security_knowledge.scope import bind_query_scope

ALLOWED_KNOWLEDGE_QUERIES: tuple[str, ...] = (
    "get_record",
    "find_by_regression_key",
    "find_related_observations",
    "compare_with_baseline",
    "list_project_regressions",
    "get_prior_verification",
)


class KnowledgeQueryPort:
    def __init__(self, store: Any):
        self._store = store
        self.history: list[dict[str, Any]] = []

    @property
    def allowed_queries(self) -> tuple[str, ...]:
        return ALLOWED_KNOWLEDGE_QUERIES

    def _record(self, query_type: str, scope: Any, result_digest: str) -> dict[str, Any]:
        from datetime import datetime

        entry = {"query_type": query_type, "audit_id": scope.audit_id, "project_id": scope.project_id, "snapshot_id": scope.snapshot_id, "timestamp": datetime.now(UTC).isoformat(), "result_digest": result_digest}
        self.history.append(entry)
        return entry

    def get_record(self, record_id: str, *, audit_id: str, project_id: str) -> tuple[Any | None, dict[str, Any]]:
        from emo_cyber_agent.threat_modeling.spec import canonical_digest

        scope = bind_query_scope(caller_audit_id=audit_id, caller_project_id=project_id)
        record = self._store.get_record(record_id, audit_id=scope.audit_id, project_id=scope.project_id)
        return record, self._record("get_record", scope, canonical_digest({"record": record.digest if record else None}))

    def find_by_regression_key(self, regression_key: str, *, audit_id: str, project_id: str) -> tuple[list[Any], dict[str, Any]]:
        from emo_cyber_agent.threat_modeling.spec import canonical_digest

        if not regression_key or not regression_key.strip():
            raise KnowledgeError(KnowledgeErrorCode.QUERY_REJECTED, "empty regression key")
        scope = bind_query_scope(caller_audit_id=audit_id, caller_project_id=project_id)
        records = self._store.find_by_regression_key(regression_key.strip(), audit_id=scope.audit_id, project_id=scope.project_id)
        return records, self._record("find_by_regression_key", scope, canonical_digest({"records": [r.record_id for r in records]}))

    def find_related_observations(self, object_id: str, *, audit_id: str, project_id: str) -> tuple[list[Any], dict[str, Any]]:
        from emo_cyber_agent.threat_modeling.spec import canonical_digest

        if not object_id or not object_id.strip() or len(object_id) > 320:
            raise KnowledgeError(KnowledgeErrorCode.QUERY_REJECTED, "invalid object id")
        scope = bind_query_scope(caller_audit_id=audit_id, caller_project_id=project_id)
        matches = [r for r in self._store.list_records(audit_id=scope.audit_id, project_id=scope.project_id) if object_id.strip() in (r.source_id, r.regression_key)]
        return matches, self._record("find_related_observations", scope, canonical_digest({"records": [r.record_id for r in matches]}))

    def compare_with_baseline(self, regression_key: str, *, audit_id: str, project_id: str, baseline_snapshot_id: str = "") -> tuple[list[Any], dict[str, Any]]:
        from emo_cyber_agent.threat_modeling.spec import canonical_digest

        scope = bind_query_scope(caller_audit_id=audit_id, caller_project_id=project_id)
        records = self._store.find_by_regression_key(regression_key, audit_id=scope.audit_id, project_id=scope.project_id)
        if baseline_snapshot_id:
            records = sorted(records, key=lambda r: (r.snapshot_id != baseline_snapshot_id, r.snapshot_id, r.record_id))
        return records, self._record("compare_with_baseline", scope, canonical_digest({"records": [r.record_id for r in records]}))

    def list_project_regressions(self, *, audit_id: str, project_id: str) -> tuple[list[Any], dict[str, Any]]:
        from emo_cyber_agent.threat_modeling.spec import canonical_digest

        scope = bind_query_scope(caller_audit_id=audit_id, caller_project_id=project_id)
        records = [r for r in self._store.list_records(audit_id=scope.audit_id, project_id=scope.project_id) if r.regression_key]
        return records, self._record("list_project_regressions", scope, canonical_digest({"records": [r.record_id for r in records]}))

    def get_prior_verification(self, context: str, *, audit_id: str, project_id: str) -> tuple[list[Any], dict[str, Any]]:
        from emo_cyber_agent.threat_modeling.spec import canonical_digest

        if not context or not context.strip():
            raise KnowledgeError(KnowledgeErrorCode.QUERY_REJECTED, "empty verification context")
        scope = bind_query_scope(caller_audit_id=audit_id, caller_project_id=project_id)
        records = [r for r in self._store.list_records(audit_id=scope.audit_id, project_id=scope.project_id) if r.category == "VERIFICATION_OUTCOME"]
        return records, self._record("get_prior_verification", scope, canonical_digest({"records": [r.record_id for r in records]}))

    def run_named(self, query_type: str, **kwargs: Any) -> tuple[Any, dict[str, Any]]:
        dispatch = {
            "get_record": lambda: self.get_record(kwargs.get("record_id", ""), audit_id=kwargs.get("audit_id", ""), project_id=kwargs.get("project_id", "")),
            "find_by_regression_key": lambda: self.find_by_regression_key(kwargs.get("regression_key", ""), audit_id=kwargs.get("audit_id", ""), project_id=kwargs.get("project_id", "")),
            "find_related_observations": lambda: self.find_related_observations(kwargs.get("object_id", ""), audit_id=kwargs.get("audit_id", ""), project_id=kwargs.get("project_id", "")),
            "compare_with_baseline": lambda: self.compare_with_baseline(kwargs.get("regression_key", ""), audit_id=kwargs.get("audit_id", ""), project_id=kwargs.get("project_id", ""), baseline_snapshot_id=kwargs.get("baseline_snapshot_id", "")),
            "list_project_regressions": lambda: self.list_project_regressions(audit_id=kwargs.get("audit_id", ""), project_id=kwargs.get("project_id", "")),
            "get_prior_verification": lambda: self.get_prior_verification(kwargs.get("context", ""), audit_id=kwargs.get("audit_id", ""), project_id=kwargs.get("project_id", "")),
        }
        try:
            handler = dispatch[query_type]
        except KeyError:
            raise KnowledgeError(KnowledgeErrorCode.QUERY_REJECTED, f"unknown knowledge query: {query_type[:80]}") from None
        return handler()
