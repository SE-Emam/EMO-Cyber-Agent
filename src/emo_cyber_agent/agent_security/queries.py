"""Agent security queries — POST-RC-010.

Fixed allowlisted surface queries over one snapshot-bound agent
model. No arbitrary graph language, no threat DSL passthrough.
Every query is audit-bound and provenance-recorded.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from emo_cyber_agent.agent_security.errors import AgentSecurityError, AgentSecurityErrorCode

ALLOWED_AGENT_QUERIES: tuple[str, ...] = (
    "list_agents",
    "list_mcp_topology",
    "list_agent_attack_surface",
    "list_agent_threats",
    "list_delegations",
    "list_capability_graph",
    "list_memories",
    "list_credentials",
)

_MAX_TARGET_LEN = 320


def _clean(value: str) -> str:
    if not isinstance(value, str):
        raise AgentSecurityError(AgentSecurityErrorCode.QUERY_REJECTED, "query target must be text")
    text = value.strip()
    if len(text) > _MAX_TARGET_LEN:
        raise AgentSecurityError(AgentSecurityErrorCode.QUERY_REJECTED, "query target too long")
    if "\x00" in text or "\n" in text or "\r" in text:
        raise AgentSecurityError(AgentSecurityErrorCode.QUERY_REJECTED, "query target carries control characters")
    return text


def _digest(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


class AgentQueryPort:
    """Read-only queries over one snapshot-bound agent assessment."""

    def __init__(self, assessment: Any):
        self._assessment = assessment
        self.history: list[dict[str, Any]] = []

    @property
    def allowed_queries(self) -> tuple[str, ...]:
        return ALLOWED_AGENT_QUERIES

    def _scope(self, audit_id: str) -> None:
        if audit_id != self._assessment.audit_id:
            raise AgentSecurityError(AgentSecurityErrorCode.CROSS_AUDIT, "query audit does not match assessment audit")

    def _record(self, query_type: str, target: str, result: Any) -> dict[str, Any]:
        entry = {
            "query_type": query_type, "target": target, "snapshot_id": self._assessment.snapshot_id,
            "timestamp": datetime.now(timezone.utc).isoformat(), "result_digest": _digest(result),
        }
        self.history.append(entry)
        return entry

    def _dump(self, items: Any) -> list[dict[str, Any]]:
        return [i.model_dump(mode="json") if hasattr(i, "model_dump") else dict(i) for i in (items or ())]

    def list_agents(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        result = self._dump(getattr(self._assessment.system, "agents", ())) if getattr(self._assessment, "system", None) else []
        return result, self._record("list_agents", "", [r.get("agent_id") for r in result])

    def list_mcp_topology(self, *, audit_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        self._scope(audit_id)
        result = dict(getattr(self._assessment, "mcp_topology", {}) or {})
        return result, self._record("list_mcp_topology", "", sorted(result))

    def list_agent_attack_surface(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        surface = getattr(self._assessment, "surface", None)
        result = self._dump(getattr(surface, "elements", ()) if surface else ())
        return result, self._record("list_agent_attack_surface", "", [r.get("element_id") for r in result])

    def list_agent_threats(self, *, audit_id: str, target: str = "") -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        wanted = _clean(target) if target else ""
        scenarios = getattr(self._assessment, "scenarios", ()) or ()
        result = [s.model_dump(mode="json") for s in scenarios if not wanted or wanted in s.scenario_id or wanted in s.category]
        return result, self._record("list_agent_threats", wanted, [r.get("scenario_id") for r in result])

    def list_delegations(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        system = getattr(self._assessment, "system", None)
        result = self._dump(getattr(system, "delegations", ()) if system else ())
        return result, self._record("list_delegations", "", [r.get("delegation_id") for r in result])

    def list_capability_graph(self, *, audit_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        self._scope(audit_id)
        result = dict(getattr(self._assessment, "capability_graph", {}) or {})
        return result, self._record("list_capability_graph", "", sorted(result))

    def list_memories(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        system = getattr(self._assessment, "system", None)
        result = self._dump(getattr(system, "memories", ()) if system else ())
        return result, self._record("list_memories", "", [r.get("entry_id") for r in result])

    def list_credentials(self, *, audit_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self._scope(audit_id)
        system = getattr(self._assessment, "system", None)
        flows = self._dump(getattr(system, "credential_flows", ()) if system else ())
        redacted = [{**f, "material": "[redacted]"} for f in flows]
        return redacted, self._record("list_credentials", "", [r.get("flow_id", "") for r in redacted])

    def run_named(self, query_type: str, *, audit_id: str, target: str = "") -> tuple[Any, dict[str, Any]]:
        dispatch = {
            "list_agents": lambda: self.list_agents(audit_id=audit_id),
            "list_mcp_topology": lambda: self.list_mcp_topology(audit_id=audit_id),
            "list_agent_attack_surface": lambda: self.list_agent_attack_surface(audit_id=audit_id),
            "list_agent_threats": lambda: self.list_agent_threats(audit_id=audit_id, target=target),
            "list_delegations": lambda: self.list_delegations(audit_id=audit_id),
            "list_capability_graph": lambda: self.list_capability_graph(audit_id=audit_id),
            "list_memories": lambda: self.list_memories(audit_id=audit_id),
            "list_credentials": lambda: self.list_credentials(audit_id=audit_id),
        }
        try:
            handler = dispatch[query_type]
        except KeyError:
            raise AgentSecurityError(AgentSecurityErrorCode.QUERY_REJECTED, f"unknown agent query: {query_type[:80]}") from None
        return handler()
