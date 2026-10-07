"""POST-T020 official template: executive-security-summary (presentation only).

Condensed management-oriented presentation. Mandatory security fields
always present; no scores, no rankings, no verdicts.
"""

from __future__ import annotations

from emo_cyber_agent.report_templates.spec import ReportTemplateSpec, TemplateSection

SPEC = ReportTemplateSpec(
    template_id="executive-security-summary",
    name="Executive Security Summary",
    version="1.0.0",
    type="executive",
    description="Condensed executive summary presentation. Mandatory security fields always present; no scores, no rankings, no verdicts.",
    sections=(
        TemplateSection(name="summary", fields=("report.summary",)),
        TemplateSection(name="scope", fields=()),
        TemplateSection(
            name="findings",
            fields=(
                "finding.finding_id",
                "finding.title",
                "finding.severity",
                "finding.confidence",
                "finding.status",
                "finding.evidence_ids",
                "finding.verification_ids",
                "finding.provenance",
            ),
        ),
        TemplateSection(name="limitations", fields=()),
    ),
    finding_fields=(
        "finding.finding_id",
        "finding.title",
        "finding.severity",
        "finding.confidence",
        "finding.status",
        "finding.category",
        "finding.evidence_ids",
        "finding.verification_ids",
        "finding.provenance",
        "finding.impact",
    ),
    section_order=("summary", "scope", "findings", "limitations"),
    show_non_reportable=False,
    evidence_presentation="references",
    verification_presentation="status",
    limitations_sections=("limitations",),
    appendices=(),
    output_formats=("json", "markdown"),
    preserve_provenance=True,
    redact_secrets=True,
    deterministic=True,
    provenance={"source": "official", "suite": "POST-T020"},
)
