"""Knowledge record construction — POST-RC-011.

Atomic pipeline: validate → canonicalize → digest → scope check
→ record. Any failure leaves no partial record: the function
either returns a complete frozen record or raises.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.security_knowledge.errors import KnowledgeError, KnowledgeErrorCode
from emo_cyber_agent.security_knowledge.spec import (
    PERSISTABLE_CATEGORIES,
    TRUST_LEVELS,
    KnowledgeProvenance,
    KnowledgeRecord,
    KnowledgeRetention,
)
from emo_cyber_agent.threat_modeling.spec import canonical_digest


def build_knowledge_record(
    *,
    audit_id: str,
    project_id: str,
    snapshot_id: str = "",
    scope_kind: str = "SNAPSHOT_BOUND",
    source_type: str,
    source_id: str,
    category: str,
    created_from_evidence_ids: tuple[str, ...] = (),
    content: dict[str, Any] | None = None,
    related_finding_id: str = "",
    verification_ref: str = "",
    regression_key: str = "",
    trust_level: str = "untrusted",
    provenance: KnowledgeProvenance | None = None,
    retention: KnowledgeRetention | None = None,
) -> tuple[KnowledgeRecord, bool]:
    """Returns (record, quarantined). Raises on any contract violation,
    leaving no partial record behind."""
    from emo_cyber_agent.security_knowledge.memory_policy import check_content

    if not audit_id or not project_id:
        raise KnowledgeError(KnowledgeErrorCode.INVALID, "record requires audit_id and project_id")
    if category not in PERSISTABLE_CATEGORIES:
        raise KnowledgeError(KnowledgeErrorCode.BANNED_CONTENT, f"category not persistable: {category}")
    if trust_level not in TRUST_LEVELS:
        raise KnowledgeError(KnowledgeErrorCode.INVALID, f"trust level not allowed: {trust_level}")
    if provenance is None:
        raise KnowledgeError(KnowledgeErrorCode.INVALID, "record requires provenance")
    quarantined = check_content(content or {}, category)
    canonical = _canonicalize(content or {})
    content_digest = canonical_digest({"content": canonical})
    digest = canonical_digest({
        "audit": audit_id, "project": project_id, "snapshot": snapshot_id,
        "scope": scope_kind, "source_type": source_type, "source_id": source_id,
        "category": category, "evidence": sorted(created_from_evidence_ids),
        "content": canonical, "finding": related_finding_id, "verification": verification_ref,
        "regression_key": regression_key,
    })
    record = KnowledgeRecord(
        record_id=f"kn-{digest[:24]}", audit_id=audit_id, project_id=project_id,
        snapshot_id=snapshot_id, scope_kind=scope_kind, source_type=source_type,
        source_id=source_id, category=category,
        created_from_evidence_ids=tuple(sorted(created_from_evidence_ids)),
        content=canonical, content_digest=content_digest,
        related_finding_id=related_finding_id, verification_ref=verification_ref,
        regression_key=regression_key, trust_level="quarantined" if quarantined else trust_level,
        provenance=provenance, digest=digest,
        retention=retention or KnowledgeRetention(),
    )
    return record, quarantined


def _canonicalize(content: dict[str, Any]) -> dict[str, Any]:
    from emo_cyber_agent.core.repository import redact_credentials

    def _scrub(value: Any) -> Any:
        if isinstance(value, str):
            return redact_credentials(value)
        if isinstance(value, dict):
            return {str(k): _scrub(v) for k, v in sorted(value.items())}
        if isinstance(value, (list, tuple)):
            return [_scrub(v) for v in value]
        return value

    return _scrub(dict(content))


def record_reference(record: KnowledgeRecord) -> Any:
    from emo_cyber_agent.security_knowledge.spec import KnowledgeReference

    return KnowledgeReference(
        record_id=record.record_id, audit_id=record.audit_id, project_id=record.project_id,
        snapshot_id=record.snapshot_id, digest=record.digest,
    )
