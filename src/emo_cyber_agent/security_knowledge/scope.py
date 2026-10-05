"""Scope enforcement — POST-RC-011.

Identity equality must be explicit: same fingerprint, same URL,
same title, or same text never implies same scope. Every record
access and every query binds to the caller's (audit, project)
and optional snapshot window; anything else is DENY.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.security_knowledge.errors import KnowledgeError, KnowledgeErrorCode
from emo_cyber_agent.security_knowledge.spec import KnowledgeAccess, KnowledgeScope


def check_record_scope(record: Any, *, audit_id: str, project_id: str, snapshot_id: str = "") -> None:
    if record.audit_id != audit_id:
        raise KnowledgeError(KnowledgeErrorCode.CROSS_AUDIT, "record belongs to a different audit")
    if record.project_id != project_id:
        raise KnowledgeError(KnowledgeErrorCode.CROSS_PROJECT, "record belongs to a different project")
    if snapshot_id and getattr(record, "snapshot_id", "") and record.snapshot_id != snapshot_id:
        raise KnowledgeError(KnowledgeErrorCode.CROSS_SNAPSHOT, "record belongs to a different snapshot")


def bind_query_scope(
    *,
    caller_audit_id: str,
    caller_project_id: str,
    requested_audit_id: str = "",
    requested_project_id: str = "",
    requested_snapshot_id: str = "",
) -> KnowledgeScope:
    """The caller cannot change the scope Core enforces: any requested
    identity outside the caller's own is DENY, including empty-vs-set
    mismatches that would widen silently."""
    if not caller_audit_id or not caller_project_id:
        raise KnowledgeError(KnowledgeErrorCode.SCOPE_DENIED, "caller scope required")
    if requested_audit_id and requested_audit_id != caller_audit_id:
        raise KnowledgeError(KnowledgeErrorCode.CROSS_AUDIT, "query scope outside caller audit")
    if requested_project_id and requested_project_id != caller_project_id:
        raise KnowledgeError(KnowledgeErrorCode.CROSS_PROJECT, "query scope outside caller project")
    forbidden = ("other_audit_id", "raw_backend_query", "path_escape", "tenant_scope", "policy_override")
    for marker in (requested_audit_id, requested_project_id, requested_snapshot_id):
        lowered = str(marker).lower()
        for token in forbidden:
            if token in lowered:
                raise KnowledgeError(KnowledgeErrorCode.QUERY_REJECTED, f"forbidden query marker: {token}")
    return KnowledgeScope(audit_id=caller_audit_id, project_id=caller_project_id, snapshot_id=requested_snapshot_id)


def access_decision(*, audit_id: str, project_id: str, operations: tuple[str, ...] = ("read",)) -> KnowledgeAccess:
    return KnowledgeAccess(audit_id=audit_id, project_id=project_id, allowed_operations=tuple(operations), reason="scope-bound read-only access")
