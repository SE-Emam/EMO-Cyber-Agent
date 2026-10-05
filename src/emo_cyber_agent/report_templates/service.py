"""Report template service — POST-RC-003 application facade.

Validate → resolve → snapshot. No rendering of security semantics here;
rendering lives in core/reporting.py and consumes snapshots only.
"""

from __future__ import annotations

from emo_cyber_agent.report_templates.registry import ReportTemplateRegistry
from emo_cyber_agent.report_templates.resolver import ReportTemplateResolver
from emo_cyber_agent.report_templates.spec import ResolvedReportTemplate
from emo_cyber_agent.report_templates.validator import ReportTemplateValidator


class ReportTemplateService:
    def __init__(self, registry: ReportTemplateRegistry):
        self._registry = registry
        self._validator = ReportTemplateValidator()
        self._resolver = ReportTemplateResolver(registry)

    @property
    def validator(self) -> ReportTemplateValidator:
        return self._validator

    def plan(self, *, template_id: str | None = None, task_type: str = "", objective: str = "") -> ResolvedReportTemplate:
        return self._resolver.resolve(template_id=template_id, task_type=task_type, objective=objective)
