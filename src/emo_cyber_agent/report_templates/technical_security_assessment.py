"""POST-T020 official template: technical-security-assessment (presentation only).

Full-detail technical presentation. Projects finding evidence verbatim;
never mutates severity, findings, policy, or state.
"""

from __future__ import annotations

from emo_cyber_agent.report_templates.spec import ReportTemplateSpec, TemplateSection

SPEC = ReportTemplateSpec(
    template_id="technical-security-assessment",
    name="Technical Security Assessment",
    version="1.0.0",
    type="security",
    description="Full technical security assessment presentation. All mandatory security fields always present; verification shown in detail.",
    sections=(
        TemplateSection(name="summary", fields=("report.summary",)),
        TemplateSection(name="scope", fields=()),
        TemplateSection(
            name="findings",
            fields=(
                "finding.finding_id",
                "finding.title",
                "finding.description",
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
            ),
        ),
        TemplateSection(name="evidence", fields=("finding.evidence_ids", "finding.provenance")),
        TemplateSection(name="verification", fields=("finding.verification_ids", "finding.status")),
        TemplateSection(name="limitations", fields=()),
    ),
    finding_fields=(
        "finding.finding_id",
        "finding.title",
        "finding.description",
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
        "finding.observed_issue",
        "finding.root_cause",
        "finding.impact",
        "finding.references",
    ),
    section_order=("summary", "scope", "findings", "evidence", "verification", "limitations"),
    show_non_reportable=False,
    evidence_presentation="references",
    verification_presentation="detailed",
    limitations_sections=("limitations",),
    appendices=("provenance",),
    output_formats=("json", "jsonl", "markdown"),
    preserve_provenance=True,
    redact_secrets=True,
    deterministic=True,
    provenance={"source": "official", "suite": "POST-T020"},
)
