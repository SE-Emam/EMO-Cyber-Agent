"""Report template validator — POST-RC-003 (declarative checks only)."""

from __future__ import annotations

import re

from emo_cyber_agent.report_templates.spec import ReportTemplateSpec, TemplateTrust


class ReportTemplateValidator:
    """Schema + safety + mandatory-field validation. Declarative only."""

    # Directives that are never allowed anywhere in template text.
    # G11-L2: all entries are lowercase because the haystack is lowered
    # before matching (`XMLHttpRequest` was dead — it could never match a
    # lowered haystack; now `xmlhttprequest`).
    UNSAFE_MARKERS = ("javascript:", "<script", "exec(", "eval(", "__import__", "os.system", "subprocess", "fetch(", "xmlhttprequest", "import ", "require(")

    # G11-L2: whitespace-tolerant variants (`require (`, `fetch (`, `eval (`,
    # `exec (`) — substring markers above miss a space before the paren.
    UNSAFE_WS_PATTERNS: tuple[re.Pattern[str], ...] = (
        re.compile(r"require\s*\("),
        re.compile(r"fetch\s*\("),
        re.compile(r"eval\s*\("),
        re.compile(r"exec\s*\("),
    )

    def validate(self, spec: ReportTemplateSpec) -> tuple[bool, TemplateTrust, tuple[str, ...], tuple[str, ...]]:
        from emo_cyber_agent.report_templates.spec import ALLOWED_FINDING_FIELDS, MANDATORY_FINDING_FIELDS

        errors: list[str] = []
        warnings: list[str] = []
        # R1: re-check the finding-field allowlist here. The pydantic
        # constructor validators enforce it, but model_copy(update=...)
        # bypasses validation, so validate() must not trust construction.
        for field in spec.finding_fields:
            if field not in ALLOWED_FINDING_FIELDS and not field.startswith("report.") and not field.startswith("meta."):
                errors.append(f"field-invalid:{field}")
        for section in spec.sections:
            for field in section.fields:
                if field not in ALLOWED_FINDING_FIELDS and not field.startswith("report.") and not field.startswith("meta."):
                    errors.append(f"field-invalid:{section.name}:{field}")
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
            for pattern in self.UNSAFE_WS_PATTERNS:
                match = pattern.search(lowered)
                if match:
                    raw = match.group(0)
                    # Stable no-space marker name (`require (` → `require(`).
                    tight = re.sub(r"\s+", "", raw)
                    if f"unsafe-directive:{tight}" not in errors:
                        errors.append(f"unsafe-directive:{tight}")
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
        # R2: this validator never confers TRUSTED. A self-claimed
        # provenance['source'] == 'official' is untrusted input, so deriving
        # trust from it would let any spec mint trust. TRUSTED is conferred
        # only by the official builders (build_official_registry /
        # load_official_registry) via Registry.register(trust=TRUSTED),
        # which re-validates before accepting TRUSTED.
        trust = TemplateTrust.UNTRUSTED
        return (not errors, trust, tuple(errors), tuple(warnings))
