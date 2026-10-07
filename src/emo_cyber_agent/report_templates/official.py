"""POST-T020 official template suite aggregator (presentation only).

Reuses the existing engine (registry / validator / resolver / service);
defines no new semantics. Templates are data fitting ReportTemplateSpec:
schema-valid, trusted, deterministic, provenance-preserving,
verification-preserving, mandatory fields non-droppable.
"""

from __future__ import annotations

from emo_cyber_agent.report_templates import agent_security_assessment as _agent
from emo_cyber_agent.report_templates import change_aware_security_review as _change
from emo_cyber_agent.report_templates import cloud_security_assessment as _cloud
from emo_cyber_agent.report_templates import executive_security_summary as _exec
from emo_cyber_agent.report_templates import mcp_security_assessment as _mcp
from emo_cyber_agent.report_templates import prompt_injection_assessment as _injection
from emo_cyber_agent.report_templates import release_security_assessment as _release
from emo_cyber_agent.report_templates import technical_security_assessment as _tech
from emo_cyber_agent.report_templates.registry import ReportTemplateRegistry
from emo_cyber_agent.report_templates.spec import (
    ReportTemplateSpec,
    ResolvedReportTemplate,
    TemplateTrust,
)
from emo_cyber_agent.report_templates.validator import ReportTemplateValidator

OFFICIAL_TEMPLATE_IDS: tuple[str, ...] = (
    "technical-security-assessment",
    "executive-security-summary",
    "agent-security-assessment",
    "prompt-injection-assessment",
    "mcp-security-assessment",
    "cloud-security-assessment",
    "change-aware-security-review",
    "release-security-assessment",
)

OFFICIAL_TEMPLATES: dict[str, ReportTemplateSpec] = {
    "technical-security-assessment": _tech.SPEC,
    "executive-security-summary": _exec.SPEC,
    "agent-security-assessment": _agent.SPEC,
    "prompt-injection-assessment": _injection.SPEC,
    "mcp-security-assessment": _mcp.SPEC,
    "cloud-security-assessment": _cloud.SPEC,
    "change-aware-security-review": _change.SPEC,
    "release-security-assessment": _release.SPEC,
}


def get_official_template(template_id: str) -> ReportTemplateSpec:
    """Return the official spec for a POST-T020 template id (KeyError if unknown)."""
    return OFFICIAL_TEMPLATES[template_id]


def build_official_registry() -> ReportTemplateRegistry:
    """Register all 8 POST-T020 specs as TRUSTED after engine validation.

    Reuses ReportTemplateRegistry + ReportTemplateValidator; raises
    TemplateError on any invalid spec (fail-closed).
    """
    from emo_cyber_agent.report_templates.spec import TemplateError, TemplateErrorCode

    validator = ReportTemplateValidator()
    registry = ReportTemplateRegistry()
    for template_id in OFFICIAL_TEMPLATE_IDS:
        spec = OFFICIAL_TEMPLATES[template_id]
        ok, _trust, errors, _warnings = validator.validate(spec)
        if not ok:
            raise TemplateError(TemplateErrorCode.INVALID, f"official template invalid {template_id}: {errors}")
        registry.register(spec, trust=TemplateTrust.TRUSTED)
    return registry


def resolve_official(template_id: str) -> ResolvedReportTemplate:
    """Resolve a POST-T020 template id to an immutable snapshot via the engine."""
    from datetime import datetime, timezone

    spec = get_official_template(template_id)
    return ResolvedReportTemplate(
        template_id=spec.template_id,
        version=spec.version,
        digest=ResolvedReportTemplate.digest_of(spec),
        resolved_at=datetime.now(timezone.utc).isoformat(),
        spec=spec,
    )
