"""Report template validator — POST-RC-003 (declarative checks only)."""

from __future__ import annotations

from emo_cyber_agent.report_templates.spec import ReportTemplateSpec, TemplateTrust


class ReportTemplateValidator:
    """Schema + safety + mandatory-field validation. Declarative only."""

    # Directives that are never allowed anywhere in template text.
    UNSAFE_MARKERS = ("javascript:", "<script", "exec(", "eval(", "__import__", "os.system", "subprocess", "fetch(", "XMLHttpRequest", "import ", "require(")

    def validate(self, spec: ReportTemplateSpec) -> tuple[bool, TemplateTrust, tuple[str, ...], tuple[str, ...]]:
        from emo_cyber_agent.report_templates.spec import MANDATORY_FINDING_FIELDS

        errors: list[str] = []
        warnings: list[str] = []
        if spec.type in ("security", "executive", "developer"):
            present = set(spec.finding_fields)
            missing = [f for f in MANDATORY_FINDING_FIELDS if f not in present]
            if missing:
                errors.append(f"mandatory-fields-missing:{','.join(missing)}")
        for fmt in spec.output_formats:
            if fmt not in ("json", "jsonl", "markdown"):
                errors.append(f"format-unsupported:{fmt}")
        haystacks = [spec.description, spec.evidence_presentation, spec.verification_presentation, *spec.limitations_sections, *spec.appendices]
        for hay in haystacks:
            lowered = (hay or "").lower()
            for marker in self.UNSAFE_MARKERS:
                if marker in lowered:
                    errors.append(f"unsafe-directive:{marker}")
        for section in spec.sections:
            for rule in section.visibility:
                if rule.operator not in ("==", "!=", "in", "not-in"):
                    errors.append(f"rule-invalid:{rule.operator}")
        if not spec.preserve_provenance:
            errors.append("provenance-removal-denied")
        if not spec.redact_secrets:
            errors.append("redaction-disabled-denied")
        if not spec.deterministic:
            errors.append("nondeterministic-denied")
        trust = TemplateTrust.UNTRUSTED
        if not errors and spec.provenance.get("source") == "official":
            trust = TemplateTrust.TRUSTED
        return (not errors, trust, tuple(errors), tuple(warnings))
