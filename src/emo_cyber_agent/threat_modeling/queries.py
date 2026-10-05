"""Attack-surface queries — POST-RC-009.

Fixed allowlisted surface queries over one snapshot-bound model.
No arbitrary graph language, no threat DSL passthrough. Every
query is audit-bound and provenance-recorded.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from emo_cyber_agent.threat_modeling.errors import ThreatModelError, ThreatModelErrorCode
from emo_cyber_agent.threat_modeling.spec import ThreatModel

ALLOWED_SURFACE_QUERIES: tuple[str, ...] = (
    "list_external_entrypoints",
    "list_state_changing_entrypoints",
    "list_trust_boundaries",
    "list_public_data_flows",
    "list_sensitive_assets",
    "list_external_dependencies",
    "list_auth_boundaries",
    "list_unprotected_state_changes",
    "list_cross_boundary_flows",
    "list_attack_paths",
)

_MAX_TARGET_LEN = 320


def _clean(value: str) -> str:
    if not isinstance(value, str):
        raise ThreatModelError(ThreatModelErrorCode.QUERY_REJECTED, "query target must be text")
    text = value.strip()
    if len(text) > _MAX_TARGET_LEN:
        raise ThreatModelError(ThreatModelErrorCode.QUERY_REJECTED, "query target too long")
    if "\x00" in text or "\n" in text or "\r" in text:
        raise ThreatModelError(ThreatModelErrorCode.QUERY_REJECTED, "query target carries control characters")
    return text


def _digest(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


class ThreatQueryPort:
    """Read-only queries over one snapshot-bound threat model."""

    def __init__(self, model: ThreatModel):
        self._model = model
        self.history: list[dict[str, Any]] = []

    @property
    def allowed_queries(self) -> tuple[str, ...]:
        return ALLOWED_SURFACE_QUERIES

    def _scope(self, audit_id: str) -> None:
        if audit_id != self._model.audit_id:
            raise ThreatModelError(ThreatModelErrorCode.CROSS_AUDIT, "query audit does not match model audit")

    def _record(self, query_type: str, target: str, result: Any) -> dict[str, Any]:
        entry = {
            "query_type": query_type, "target": target, "snapshot_id": self._model.snapshot_id,
            "timestamp": datetime.now(timezone.utc).isoformat(), "result_digest": _digest(result),
        }
        self.history.append(entry)
        return entry

    def _surface_elements(self, category: str) -> list[Any]:
        if self._model.surface is None:
            return []
        return [e for e in self._model.surface.elements if e.category == category]

    def list_external_entrypoints(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        result = [e.model_dump(mode="json") for e in self._surface_elements("INBOUND")]
        return result, self._record("list_external_entrypoints", "", [r.get("element_id") for r in result])

    def list_state_changing_entrypoints(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        result = [e.model_dump(mode="json") for e in self._surface_elements("STATE_CHANGE")]
        return result, self._record("list_state_changing_entrypoints", "", [r.get("element_id") for r in result])

    def list_trust_boundaries(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        result = [b.model_dump(mode="json") for b in (self._model.system.boundaries if self._model.system else ())]
        return result, self._record("list_trust_boundaries", "", [r.get("boundary_id") for r in result])

    def list_public_data_flows(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        flows = [f.model_dump(mode="json") for f in (self._model.system.flows if self._model.system else ())]
        return flows, self._record("list_public_data_flows", "", [r.get("flow_id") for r in flows])

    def list_sensitive_assets(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        result = [a.model_dump(mode="json") for a in (self._model.system.assets if self._model.system else ())]
        return result, self._record("list_sensitive_assets", "", [r.get("asset_id") for r in result])

    def list_external_dependencies(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        result = [e.model_dump(mode="json") for e in self._surface_elements("DATA_ACCESS")]
        return result, self._record("list_external_dependencies", "", [r.get("element_id") for r in result])

    def list_auth_boundaries(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        result = [b.model_dump(mode="json") for b in (self._model.system.boundaries if self._model.system else ()) if b.kind in ("AUTHORIZATION", "AUTHENTICATION")]
        return result, self._record("list_auth_boundaries", "", [r.get("boundary_id") for r in result])

    def list_unprotected_state_changes(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        result = [e.model_dump(mode="json") for e in self._surface_elements("STATE_CHANGE")]
        return result, self._record("list_unprotected_state_changes", "", [r.get("element_id") for r in result])

    def list_cross_boundary_flows(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        result = [f.model_dump(mode="json") for f in (self._model.system.flows if self._model.system else ()) if f.crosses]
        return result, self._record("list_cross_boundary_flows", "", [r.get("flow_id") for r in result])

    def list_attack_paths(self, *, audit_id: str, target: str = "") -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        wanted = _clean(target) if target else ""
        result = [p.model_dump(mode="json") for p in self._model.attack_paths if not wanted or wanted in p.target_asset_id or wanted in p.path_id]
        return result, self._record("list_attack_paths", wanted, [r.get("path_id") for r in result])

    def run_named(self, query_type: str, *, audit_id: str, target: str = "") -> tuple[Any, dict[str, Any]]:
        """Dispatch by allowlisted name only. Anything else is rejected —
        there is no DSL to inject into."""
        dispatch = {
            "list_external_entrypoints": lambda: self.list_external_entrypoints(audit_id=audit_id),
            "list_state_changing_entrypoints": lambda: self.list_state_changing_entrypoints(audit_id=audit_id),
            "list_trust_boundaries": lambda: self.list_trust_boundaries(audit_id=audit_id),
            "list_public_data_flows": lambda: self.list_public_data_flows(audit_id=audit_id),
            "list_sensitive_assets": lambda: self.list_sensitive_assets(audit_id=audit_id),
            "list_external_dependencies": lambda: self.list_external_dependencies(audit_id=audit_id),
            "list_auth_boundaries": lambda: self.list_auth_boundaries(audit_id=audit_id),
            "list_unprotected_state_changes": lambda: self.list_unprotected_state_changes(audit_id=audit_id),
            "list_cross_boundary_flows": lambda: self.list_cross_boundary_flows(audit_id=audit_id),
            "list_attack_paths": lambda: self.list_attack_paths(audit_id=audit_id, target=target),
        }
        try:
            handler = dispatch[query_type]
        except KeyError:
            raise ThreatModelError(ThreatModelErrorCode.QUERY_REJECTED, f"unknown surface query: {query_type[:80]}") from None
        return handler()
