"""Memory policy — POST-RC-011.

What may persist, what must not, and how stored text is judged.
Secrets are rejected by redact-diff (deterministic: any text the
redactor changes is secret-bearing). Verdict vocabulary
quarantines (inert data, never authority). Repetition never
raises trust: the service stores no trust scores at all.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.security_knowledge.errors import KnowledgeError, KnowledgeErrorCode
from emo_cyber_agent.security_knowledge.spec import (
    PERSISTABLE_CATEGORIES,
    assert_no_knowledge_verdicts,
)


def check_category(category: str) -> None:
    if category not in PERSISTABLE_CATEGORIES:
        raise KnowledgeError(KnowledgeErrorCode.BANNED_CONTENT, f"category not persistable: {category}")


def check_content(content: dict[str, Any], category: str) -> bool:
    """Returns quarantined flag. Raises on secrets and banned categories."""
    from emo_cyber_agent.core.repository import redact_credentials

    check_category(category)
    text = _flatten(content)
    if redact_credentials(text) != text:
        raise KnowledgeError(KnowledgeErrorCode.SECRET_MATERIAL, "secret-bearing content denied persistence")
    try:
        assert_no_knowledge_verdicts(text)
        return False
    except KnowledgeError as e:
        if e.code == KnowledgeErrorCode.VERDICT_CAPPED:
            return True
        raise


def _flatten(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_flatten(v) for _, v in sorted(value.items()))
    if isinstance(value, (list, tuple)):
        return " ".join(_flatten(v) for v in value)
    return str(value)


def retention_metadata(
    *,
    retention_class: str = "audit-lifetime",
    created_at: str = "",
    expires_at: str = "",
    legal_hold: bool = False,
    retention_reason: str = "",
) -> dict[str, Any]:
    """Expiration is metadata only. No scheduler, no automated deletion."""
    from emo_cyber_agent.security_knowledge.spec import KnowledgeRetention

    return KnowledgeRetention(
        retention_class=retention_class, created_at=created_at, expires_at=expires_at,
        legal_hold=legal_hold, retention_reason=retention_reason,
    ).model_dump(mode="json")
