"""Report template resolver — POST-RC-003 (deterministic, no LLM)."""

from __future__ import annotations

from datetime import datetime, timezone

from emo_cyber_agent.report_templates.registry import ReportTemplateRegistry
from emo_cyber_agent.report_templates.spec import ResolvedReportTemplate, TemplateError, TemplateErrorCode


class ReportTemplateResolver:
    """Task/objective → template. Deterministic; no LLM; no execution."""

    def __init__(self, registry: ReportTemplateRegistry):
        self._registry = registry

    _BY_TASK_TYPE = {"audit": "security-audit", "review": "developer-security", "verification_support": "developer-security", "threat_model": "threat-model"}
    _BY_OBJECTIVE_KEYWORD = (
        ("executive", "executive-security"), ("developer", "developer-security"), ("web", "web-app-security"),
        ("api", "api-security"), ("supabase", "supabase-security"), ("dependen", "dependency-security"),
        ("supply", "supply-chain-security"), (" ai", "ai-security"), ("mcp", "mcp-security"),
        ("threat", "threat-model"), ("release", "pre-release-security"), ("regress", "regression-security"),
        ("authent", "authentication-security"), ("authoriz", "authorization-security"), ("database", "database-security"),
        ("business-logic", "business-logic-security"), ("cloud", "cloud-security"), ("container", "container-security"),
        ("agent", "agent-security"),
    )

    def resolve(self, *, template_id: str | None = None, task_type: str = "", objective: str = "") -> ResolvedReportTemplate:
        if template_id:
            try:
                spec = self._registry.get(template_id)
            except TemplateError as e:
                raise TemplateError(TemplateErrorCode.NOT_FOUND, str(e)) from e
            return self._snapshot(spec)
        lowered = f" {(objective or '').lower()} "
        for keyword, target in self._BY_OBJECTIVE_KEYWORD:
            if keyword in lowered:
                try:
                    return self._snapshot(self._registry.get(target))
                except TemplateError:
                    break
        fallback = self._BY_TASK_TYPE.get(task_type, "security-audit")
        try:
            return self._snapshot(self._registry.get(fallback))
        except TemplateError as e:
            raise TemplateError(TemplateErrorCode.NOT_FOUND, f"no template for task type {task_type}") from e

    def _snapshot(self, spec) -> ResolvedReportTemplate:
        return ResolvedReportTemplate(template_id=spec.template_id, version=spec.version, digest=ResolvedReportTemplate.digest_of(spec), resolved_at=datetime.now(timezone.utc).isoformat(), spec=spec)
