"""Knowledge template loading — POST-RC-011.

YAML templates under templates/security-knowledge/ are declarative
authoring contracts only: they constrain which categories a profile
may persist and which scope rules apply. They never grant authority
and never widen a caller's scope.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from emo_cyber_agent.security_knowledge.errors import KnowledgeError, KnowledgeErrorCode
from emo_cyber_agent.security_knowledge.spec import PERSISTABLE_CATEGORIES, KnowledgeTemplateConfig


def load_knowledge_template(path: Any) -> KnowledgeTemplateConfig:
    try:
        import yaml as _yaml
    except ImportError as e:  # pragma: no cover - dependency guard
        raise KnowledgeError(KnowledgeErrorCode.INVALID, "YAML parsing needs pyyaml") from e

    try:
        doc = _yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        raise KnowledgeError(KnowledgeErrorCode.INVALID, f"malformed template YAML: {e}") from e
    if not isinstance(doc, dict) or "knowledge_template" not in doc:
        raise KnowledgeError(KnowledgeErrorCode.INVALID, "template YAML must contain a top-level knowledge_template mapping")
    raw = doc["knowledge_template"]
    if not isinstance(raw, dict):
        raise KnowledgeError(KnowledgeErrorCode.INVALID, "knowledge_template must be a mapping")
    try:
        template = KnowledgeTemplateConfig(
            template_id=str(raw.get("template_id", "")),
            name=str(raw.get("name", "")),
            version=str(raw.get("version", "")),
            allowed_categories=tuple(raw.get("allowed_categories", ()) or ()),
            default_retention_class=str(raw.get("default_retention_class", "audit-lifetime")),
            scope_rules=tuple(raw.get("scope_rules", ()) or ()),
            provenance=dict(doc.get("provenance", {}) or {}),
        )
    except ValueError as e:
        raise KnowledgeError(KnowledgeErrorCode.INVALID, f"template invalid: {e}") from e
    for category in template.allowed_categories:
        if category not in PERSISTABLE_CATEGORIES:
            raise KnowledgeError(KnowledgeErrorCode.BANNED_CONTENT, f"template allows non-persistable category: {category}")
    return template


def load_official_knowledge_templates(directory: Any) -> list[KnowledgeTemplateConfig]:
    paths = sorted(Path(directory).glob("*.yaml"))
    if not paths:
        raise KnowledgeError(KnowledgeErrorCode.INVALID, f"no knowledge templates in {directory}")
    templates = [load_knowledge_template(path) for path in paths]
    for template in templates:
        if template.provenance.get("source") != "official":
            raise KnowledgeError(KnowledgeErrorCode.PROVENANCE_FORGED, f"official template lacks official provenance: {template.template_id}")
    ids = [t.template_id for t in templates]
    if len(set(ids)) != len(ids):
        raise KnowledgeError(KnowledgeErrorCode.DUPLICATE_REGION, "duplicate knowledge template ids")
    return templates
