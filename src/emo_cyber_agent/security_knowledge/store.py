"""Knowledge store port + in-memory implementation — POST-RC-011.

Core Port only: Core never knows the storage engine. Writes are
atomic (validate → canonicalize → digest → scope check → persist;
any failure leaves no partial record). Duplicate inserts are
idempotent by digest identity. No global namespace exists: every
key is (audit, project, record) and cross-scope reads are DENY.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from emo_cyber_agent.security_knowledge.errors import KnowledgeError, KnowledgeErrorCode


class SecurityKnowledgeStore(ABC):
    """Core Port. Future engines (file/database/remote) implement this."""

    @abstractmethod
    def store_record(self, record: Any) -> str:
        """Persist a complete record, return its record_id. Idempotent."""

    @abstractmethod
    def get_record(self, record_id: str, *, audit_id: str, project_id: str) -> Any | None:
        """Scope-bound fetch. Cross-scope access raises, never leaks."""

    @abstractmethod
    def find_by_regression_key(self, regression_key: str, *, audit_id: str, project_id: str) -> list[Any]:
        """Scope-bound regression-key lookup, deterministic order."""

    @abstractmethod
    def list_records(self, *, audit_id: str, project_id: str, namespace: str = "") -> list[Any]:
        """Scope-bound listing, deterministic order."""


class InMemoryKnowledgeStore(SecurityKnowledgeStore):
    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str], Any] = {}
        self._by_regression: dict[tuple[str, str, str], list[str]] = {}
        self._namespaces: dict[tuple[str, str, str], str] = {}

    def store_record(self, record: Any, *, namespace: str = "") -> str:
        key = (record.audit_id, record.project_id, record.record_id)
        if key in self._records:
            existing = self._records[key]
            if existing.digest != record.digest:
                raise KnowledgeError(KnowledgeErrorCode.DUPLICATE_REGION, "conflicting record identity: same id, different digest")
            return str(existing.record_id)
        self._records[key] = record
        self._namespaces[key] = namespace
        if getattr(record, "regression_key", ""):
            index_key = (record.audit_id, record.project_id, str(record.regression_key))
            bucket = self._by_regression.setdefault(index_key, [])
            if record.record_id not in bucket:
                bucket.append(record.record_id)
                bucket.sort()
        return str(record.record_id)

    def get_record(self, record_id: str, *, audit_id: str, project_id: str, namespace: str = "") -> Any | None:
        key = (audit_id, project_id, record_id)
        record = self._records.get(key)
        if record is None:
            return None
        if namespace and self._namespaces.get(key, "") != namespace:
            raise KnowledgeError(KnowledgeErrorCode.SCOPE_DENIED, "record lives in a different namespace")
        return record

    def find_by_regression_key(self, regression_key: str, *, audit_id: str, project_id: str, namespace: str = "") -> list[Any]:
        out = []
        for record_id in self._by_regression.get((audit_id, project_id, regression_key), []):
            record = self.get_record(record_id, audit_id=audit_id, project_id=project_id, namespace=namespace)
            if record is not None:
                out.append(record)
        return out

    def list_records(self, *, audit_id: str, project_id: str, namespace: str = "") -> list[Any]:
        out = []
        for (record_audit, record_project, _), record in sorted(self._records.items()):
            if record_audit != audit_id or record_project != project_id:
                continue
            if namespace and self._namespaces.get((record_audit, record_project, record.record_id), "") != namespace:
                continue
            out.append(record)
        return out
