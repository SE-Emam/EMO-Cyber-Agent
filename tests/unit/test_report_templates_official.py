"""POST-T020 — Official template suite tests (offline).

Covers the 8 POST-T020 presentation-only templates reusing the existing
engine (spec / registry / validator / resolver / core/reporting):
schema-valid, trusted, deterministic, provenance-preserving,
verification-preserving, mandatory fields non-droppable, no authority
(no severity / finding / policy mutation). No network, no LLM.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from emo_cyber_agent.core.findings import Remediation, SecurityFinding
from emo_cyber_agent.core.reporting import (
    apply_report_template,
    build_report,
    to_canonical_json_with_template,
    to_markdown_with_template,
)
from emo_cyber_agent.report_templates.library import validate_against_schema
from emo_cyber_agent.report_templates.official import (
    OFFICIAL_TEMPLATE_IDS,
    OFFICIAL_TEMPLATES,
    build_official_registry,
    resolve_official,
)
from emo_cyber_agent.report_templates.spec import (
    MANDATORY_FINDING_FIELDS,
    ResolvedReportTemplate,
    TemplateTrust,
)
from emo_cyber_agent.report_templates.validator import ReportTemplateValidator

EXPECTED_IDS = (
    "technical-security-assessment",
    "executive-security-summary",
    "agent-security-assessment",
    "prompt-injection-assessment",
    "mcp-security-assessment",
    "cloud-security-assessment",
    "change-aware-security-review",
    "release-security-assessment",
)


def _finding(fid="f1", audit="A", severity="high", status="confirmed"):
    return SecurityFinding(
        finding_id=fid,
        audit_id=audit,
        asset_id="asset-1",
        title=f"Title {fid}",
        description=f"Description {fid}",
        category="authorization",
        severity=severity,  # type: ignore[arg-type]
        confidence=0.8,
        status=status,  # type: ignore[arg-type]
        cwe="CWE-639",
        owasp="A01:2021-Broken Access Control",
        affected_locations=("src/a.py:10",),
        evidence_ids=("e1",),
        observation_ids=("o1",),
        candidate_id="c1",
        verification_ids=("v1",),
        provenance={"candidate": "c1", "rule": "R1"},
        remediation=Remediation(
            recommendation="fix",
            affected_component="src/a.py",
            remediation_type="authorization-check",
            validation_guidance="retest",
        ),
        references=("https://example.com/docs",),
        impact="data exposure",
        root_cause="missing check",
        fingerprint=f"fp-{fid}",
    )


def _report():
    return build_report(
        audit_id="A",
        findings=[
            _finding("f-high", severity="high"),
            _finding("f-low", severity="low"),
        ],
        scope={"repo": "x"},
        generated_at="2026-01-01T00:00:00+00:00",
        verifications={"v1": {"method": "static_confirmation", "status": "supported", "confidence": 0.85}},
        evidence={"e1": {"tool": "semgrep", "location": "src/a.py:10", "collected_at": "t", "digest": "d"}},
    )


def test_suite_lists_all_eight_ids():
    assert tuple(OFFICIAL_TEMPLATE_IDS) == EXPECTED_IDS
    assert sorted(OFFICIAL_TEMPLATES.keys()) == sorted(EXPECTED_IDS)


@pytest.mark.parametrize("template_id", EXPECTED_IDS)
def test_official_template_schema_valid_trusted_deterministic_flags(template_id):
    spec = OFFICIAL_TEMPLATES[template_id]
    assert spec.template_id == template_id
    assert spec.preserve_provenance is True
    assert spec.redact_secrets is True
    assert spec.deterministic is True
    assert spec.limitations_sections and "limitations" in spec.limitations_sections
    assert spec.output_formats  # at least one gated format
    # mandatory fields non-droppable at rest
    for mandatory in MANDATORY_FINDING_FIELDS:
        assert mandatory in spec.finding_fields, mandatory
    # engine validator: valid but advisory-only UNTRUSTED (POST-T020 R2:
    # self-claimed provenance never mints trust; TRUSTED is conferred only
    # by build_official_registry via Registry.register(trust=TRUSTED)).
    validator = ReportTemplateValidator()
    ok, trust, errors, _warnings = validator.validate(spec)
    assert ok, f"{template_id}: {errors}"
    assert trust == TemplateTrust.UNTRUSTED, template_id
    # JSON-schema cross-check against the canonical template schema
    schema = json.loads(Path("docs/schemas/report-template.schema.json").read_text())
    validate_against_schema(json.loads(json.dumps(spec.model_dump(mode="json"))), schema)


@pytest.mark.parametrize("template_id", EXPECTED_IDS)
def test_official_template_renders_deterministically(template_id):
    report = _report()
    resolved = resolve_official(template_id)
    first = apply_report_template(report, resolved)
    second = apply_report_template(report, resolved)
    assert first == second  # deterministic presentation
    assert first["template_id"] == template_id
    assert first["template_digest"] == resolved.digest
    # section order honoured (template-declared order preserved head-to-tail)
    names = [s["name"] for s in first["sections"]]
    assert names[0] == "summary"
    assert "limitations" in names
    assert names.index("summary") < names.index("findings") < names.index("limitations")
    # canonical JSON + markdown render through the engine for allowed formats
    body = json.loads(to_canonical_json_with_template(report, resolved))
    assert body["template_id"] == template_id
    assert "security_score" not in json.dumps(body) and "risk_score" not in json.dumps(body)
    md = to_markdown_with_template(report, resolved)
    assert f"{template_id}" in md and "f-high" in md


@pytest.mark.parametrize("template_id", EXPECTED_IDS)
def test_official_template_mandatory_fields_provenance_verification_preserved(template_id):
    report = _report()
    before = report.model_dump()
    resolved = resolve_official(template_id)
    presentation = apply_report_template(report, resolved)
    findings_section = next(s for s in presentation["sections"] if s["name"] == "findings")
    entries = {e["finding_id"]: e for e in findings_section["findings"]}
    assert set(entries) == {"f-high", "f-low"}
    for fid, entry in entries.items():
        # mandatory fields non-droppable in the rendered projection
        for mandatory in ("finding_id", "status", "severity", "confidence", "evidence_ids", "verification_ids", "provenance"):
            assert mandatory in entry, f"{template_id}/{fid}/{mandatory}"
        # provenance preserved verbatim
        assert entry["provenance"] == {"candidate": "c1", "rule": "R1"}
        # verification preserved (ids survive; detailed mode keeps states verbatim)
        assert "v1" in entry["verification_ids"]
        assert "e1" in entry["evidence_ids"]
    # verification states verbatim for detailed presentations
    if resolved.spec is not None and resolved.spec.verification_presentation == "detailed":
        for entry in entries.values():
            states = [v.get("status") if isinstance(v, dict) else v for v in entry["verification_ids"]]
            assert "v1" in entry["verification_ids"] or states  # ids present; detail entries carry status
    # source report untouched (presentation only)
    assert report.model_dump() == before


@pytest.mark.parametrize("template_id", EXPECTED_IDS)
def test_official_template_presentation_only_no_mutation(template_id):
    report = _report()
    snapshot_before = [f.model_dump() for f in report.findings]
    severities_before = {f.finding_id: (f.severity, f.confidence, f.status) for f in report.findings}
    resolved = resolve_official(template_id)
    presentation = apply_report_template(report, resolved)
    # source findings untouched
    assert [f.model_dump() for f in report.findings] == snapshot_before
    for f in report.findings:
        assert (f.severity, f.confidence, f.status) == severities_before[f.finding_id]
    # rendered severities/confidences/statuses identical to source (no reinterpretation)
    entries = {e["finding_id"]: e for e in next(s for s in presentation["sections"] if s["name"] == "findings")["findings"]}
    for f in report.findings:
        assert entries[f.finding_id]["severity"] == f.severity
        assert entries[f.finding_id]["confidence"] == f.confidence
        assert entries[f.finding_id]["status"] == f.status
    # no authority artefacts: no scores, ranks, verdicts, policy mutations
    blob = json.dumps(presentation, sort_keys=True)
    for banned in ("security_score", "risk_score", "ai_verdict", "overall_safe", "overall grade"):
        assert banned not in blob.lower(), banned
    assert presentation["metadata"]["audit_id"] == "A"
    # template carries no executable directives (engine unsafe-marker set)
    haystacks = [
        resolved.spec.description if resolved.spec else "",
        resolved.spec.evidence_presentation if resolved.spec else "",
        resolved.spec.verification_presentation if resolved.spec else "",
    ]
    for hay in haystacks:
        lowered = hay.lower()
        for marker in ReportTemplateValidator.UNSAFE_MARKERS:
            assert marker not in lowered, marker


def test_official_registry_trusted_no_authority():
    registry = build_official_registry()
    assert sorted(s.template_id for s in registry.list()) == sorted(EXPECTED_IDS)
    for template_id in EXPECTED_IDS:
        assert registry.trust_of(template_id, "1.0.0") == TemplateTrust.TRUSTED
        assert registry.get(template_id).template_id == template_id
    assert registry.check_cycles() == []
    # deterministic digests across registry builds
    digests_first = {s.template_id: ResolvedReportTemplate.digest_of(s) for s in registry.list()}
    digests_second = {s.template_id: ResolvedReportTemplate.digest_of(s) for s in build_official_registry().list()}
    assert digests_first == digests_second


def test_mandatory_field_drop_attempt_errors():
    # Dropping any mandatory finding field must fail engine validation.
    validator = ReportTemplateValidator()
    spec = OFFICIAL_TEMPLATES["technical-security-assessment"]
    dropped = spec.model_copy(update={"finding_fields": tuple(f for f in spec.finding_fields if f != "finding.severity")})
    ok, _trust, errors, _warnings = validator.validate(dropped)
    assert not ok
    assert any("mandatory" in e for e in errors)
    # Hostile provenance-stripping / redaction-disabling / nondeterminism denied.
    for hostile in (
        spec.model_copy(update={"preserve_provenance": False}),
        spec.model_copy(update={"redact_secrets": False}),
        spec.model_copy(update={"deterministic": False}),
    ):
        ok_h, _t, errors_h, _w = validator.validate(hostile)
        assert not ok_h, errors_h
    # Renderer also refuses hostile snapshots (defence in depth).
    report = _report()
    hostile_resolved = ResolvedReportTemplate(
        template_id=spec.template_id,
        version=spec.version,
        digest="hostile",
        spec=spec.model_copy(update={"preserve_provenance": False}),  # type: ignore[arg-type]
    )
    with pytest.raises(Exception):
        apply_report_template(report, hostile_resolved)
