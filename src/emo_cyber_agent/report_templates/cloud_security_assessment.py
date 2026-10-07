"""POST-T020 official template: cloud-security-assessment (presentation only).

Cloud-configuration presentation. Core semantics identical; presentation
only.
"""

from __future__ import annotations

from emo_cyber_agent.report_templates.spec import ReportTemplateSpec, TemplateSection

SPEC = ReportTemplateSpec(
    template_id="cloud-security-assessment",
    name="Cloud Security Assessment",
    version="1.0.0",
    type="security",
    description="Cloud-configuration assessment presentation. Mandatory security fields always present; verification preserved verbatim.",
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
                "finding.category",
                "finding.locations",
                "finding.evidence_ids",
                "finding.verification_ids",
                "finding.remediation",
                "finding.provenance",
            ),
        ),
        TemplateSection(name="verification", fields=("finding.verification_ids", "finding.status")),
        TemplateSection(name="limitations", fields=()),
    ),
    finding_fields=(
        "finding.finding_id",
        "finding.title",
        "finding.severity",
        "finding.confidence",
        "finding.status",
        "finding.category",
        "finding.cwe",
        "finding.owasp",
        "finding.locations",
        "finding.evidence_ids",
        "finding.verification_ids",
        "finding.remediation",
        "finding.provenance",
        "finding.asset_id",
        "finding.candidate_id",
        "finding.impact",
        "finding.references",
    ),
    section_order=("summary", "scope", "findings", "verification", "limitations"),
    show_non_reportable=False,
    evidence_presentation="references",
    verification_presentation="status",
    limitations_sections=("limitations",),
    appendices=("provenance",),
    output_formats=("json", "jsonl", "markdown"),
    preserve_provenance=True,
    redact_secrets=True,
    deterministic=True,
    provenance={"source": "official", "suite": "POST-T020"},
)
