"""POST-RC-003 — Report template engine tests (offline).

Spec, registry, validator, YAML loader, official library (20 templates),
resolver, composition, template-aware renderer (core/reporting.py),
task integration, security negatives. No execution, no network, no LLM.
"""

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
from emo_cyber_agent.report_templates.library import (
    load_official_registry,
    normalize_template_dict,
    spec_from_yaml_text,
    validate_against_schema,
)
from emo_cyber_agent.report_templates.registry import ReportTemplateRegistry
from emo_cyber_agent.report_templates.resolver import ReportTemplateResolver
from emo_cyber_agent.report_templates.service import ReportTemplateService
from emo_cyber_agent.report_templates.spec import (
    ReportTemplateSpec,
    ResolvedReportTemplate,
    TemplateError,
    TemplateErrorCode,
    TemplateTrust,
)
from emo_cyber_agent.report_templates.validator import ReportTemplateValidator

OFFICIAL_DIR = Path("templates/reports/official")


def _spec(template_id="demo-report", **over):
    base = dict(
        template_id=template_id, name="Demo", version="1.0.0", type="security",
        description="demo", sections=({"name": "summary", "fields": ["report.summary"]}, {"name": "findings", "fields": ["finding.title"]}),
        finding_fields=["finding.finding_id", "finding.title", "finding.severity", "finding.confidence", "finding.status", "finding.evidence_ids", "finding.verification_ids", "finding.provenance"],
        section_order=["summary", "findings", "limitations"], show_non_reportable=False,
        evidence_presentation="references", verification_presentation="status",
        limitations_sections=["limitations"], appendices=[], output_formats=["json", "jsonl", "markdown"],
        provenance={"source": "official"},
    )
    base.update(over)
    return ReportTemplateSpec(**base)  # type: ignore[arg-type]


def _finding(fid="f1", audit="A", severity="high", status="confirmed"):
    return SecurityFinding(
        finding_id=fid, audit_id=audit, asset_id="asset-1", title="T", description="D",
        category="authorization", severity=severity, confidence=0.8, status=status,
        cwe="CWE-639", owasp="A01:2021-Broken Access Control", affected_locations=("src/a.py:10",),
        evidence_ids=("e1",), observation_ids=("o1",), candidate_id="c1", verification_ids=("v1",),
        provenance={"candidate": "c1", "rule": "R1"}, remediation=Remediation(recommendation="fix", affected_component="src/a.py", remediation_type="authorization-check", validation_guidance="retest"),
        references=("https://example.com/docs",), impact="data exposure", root_cause="missing check", fingerprint=f"fp-{fid}",
    )


def _report():
    return build_report(audit_id="A", findings=[_finding("f1"), _finding("f2", severity="low")], scope={"repo": "x"}, generated_at="2026-01-01T00:00:00+00:00")


def _resolved(spec=None):
    s = spec or _spec()
    return ResolvedReportTemplate(template_id=s.template_id, version=s.version, digest=ResolvedReportTemplate.digest_of(s), spec=s)


# ---------------- spec ----------------

def test_spec_ids_versions_fields():
    s = _spec()
    assert s.template_id == "demo-report"
    with pytest.raises(Exception):
        _spec(template_id="Bad_ID")
    with pytest.raises(Exception):
        _spec(template_id="other", version="1.0")
    with pytest.raises(Exception):
        _spec(template_id="other", finding_fields=["finding.nope"])
    with pytest.raises(Exception):
        _spec(template_id="other", output_formats=["pdf"])
    with pytest.raises(Exception):
        _spec(template_id="other", sections=({"name": "x", "fields": ["finding.title"], "visibility": [{"show_if_field": "finding.title", "operator": "==", "value": "x"}]},))


def test_operators_allowlist():
    with pytest.raises(Exception):
        ReportTemplateSpec(template_id="ab1", name="N", version="1.0.0", sections=({"name": "s", "fields": [], "visibility": [{"show_if_field": "finding.severity", "operator": "contains", "value": "high"}]},), finding_fields=[], output_formats=["json"])


# ---------------- registry ----------------

def test_registry_duplicate_version_trust_cycles():
    reg = ReportTemplateRegistry()
    reg.register(_spec("aaa"), trust=TemplateTrust.TRUSTED)
    with pytest.raises(TemplateError):
        reg.register(_spec("aaa"), trust=TemplateTrust.TRUSTED)
    reg.register(_spec("aaa", version="1.0.1"))
    assert reg.get("aaa").version == "1.0.1"
    assert reg.trust_of("aaa", "1.0.0") == TemplateTrust.TRUSTED
    assert reg.check_cycles() == []
    # unregister protection when extended
    child = _spec("bbb", extends="aaa")
    reg.register(child)
    with pytest.raises(TemplateError):
        reg.unregister("aaa", "1.0.1")
    cyc = ReportTemplateRegistry()
    cyc.register(_spec("ccc", extends="ddd"))
    cyc.register(_spec("ddd", extends="ccc"))
    assert cyc.check_cycles() != []


# ---------------- validator ----------------

def test_validator_mandatory_security_negatives():
    v = ReportTemplateValidator()
    ok, trust, errors, _ = v.validate(_spec())
    # POST-T020 R2: validator is advisory only and never confers TRUSTED
    # (self-claimed provenance must not mint trust); TRUSTED is conferred
    # only by the official builders via Registry.register(trust=TRUSTED).
    assert ok and trust == TemplateTrust.UNTRUSTED
    ok2, _, errors2, _ = v.validate(_spec("nxt", finding_fields=["finding.title"], provenance={}))
    assert not ok2 and any("mandatory" in e for e in errors2)
    for bad in ["javascript:alert(1)", "<script>alert(1)</script>", "exec(malicious)"]:
        s = _spec(f"bad-{abs(hash(bad)) % 99999}", description=f"see {bad}")
        okb, _, errsb, _ = v.validate(s)
        assert not okb, bad
    s2 = _spec("noprov", preserve_provenance=False)
    okc, _, errsc, _ = v.validate(s2)
    assert not okc and "provenance-removal-denied" in errsc
    s3 = _spec("noredact", redact_secrets=False)
    okd, _, errsd, _ = v.validate(s3)
    assert not okd and "redaction-disabled-denied" in errsd


def test_validator_rechecks_allowlist_after_model_copy():
    # POST-T020 R1: pydantic constructor validators are bypassed by
    # model_copy(update=...), so validate() must re-check allowlists.
    from emo_cyber_agent.report_templates.spec import TemplateSection

    v = ReportTemplateValidator()
    hostile_fields = _spec().model_copy(update={"finding_fields": ("finding.title", "finding.nope")})
    ok, _, errors, _ = v.validate(hostile_fields)
    assert not ok and any("field-invalid" in e for e in errors)
    evil_section = TemplateSection.model_construct(name="evil", fields=("finding.nope",), visibility=())
    hostile_sections = _spec().model_copy(update={"sections": _spec().sections + (evil_section,)})
    ok2, _, errors2, _ = v.validate(hostile_sections)
    assert not ok2 and any("field-invalid" in e for e in errors2)
    # report./meta. prefixes stay allowed
    allowed = _spec().model_copy(update={"finding_fields": _spec().finding_fields + ("report.summary", "meta.note")})
    oka, _, _, _ = v.validate(allowed)
    assert oka


def test_validator_never_confers_trusted_and_registry_enforces():
    # POST-T020 R2: self-claimed provenance must not mint TRUSTED.
    v = ReportTemplateValidator()
    ok, trust, _, _ = v.validate(_spec("self-claim"))
    assert ok and trust == TemplateTrust.UNTRUSTED
    reg = ReportTemplateRegistry()
    reg.register(_spec("ok-official"), trust=TemplateTrust.TRUSTED)
    assert reg.trust_of("ok-official", "1.0.0") == TemplateTrust.TRUSTED
    with pytest.raises(TemplateError):  # non-official provenance cannot take TRUSTED
        reg.register(_spec("evil-no-claim", provenance={}), trust=TemplateTrust.TRUSTED)
    with pytest.raises(TemplateError):  # invalid specs cannot take TRUSTED either
        bad = _spec("bad-fields").model_copy(update={"finding_fields": ("finding.title", "finding.nope")})
        reg.register(bad, trust=TemplateTrust.TRUSTED)


# --- POST-T020 G11 (L1/L2) ---


def test_g11_l2_dead_marker_and_spacing_variants_flagged():
    # L2: `XMLHttpRequest` (mixed case) was dead against a lowered haystack;
    # spacing variants (`require (`, `fetch (`, `eval (`) were missed.
    v = ReportTemplateValidator()
    assert "xmlhttprequest" in ReportTemplateValidator.UNSAFE_MARKERS
    assert "XMLHttpRequest" not in ReportTemplateValidator.UNSAFE_MARKERS
    for bad in (
        "see XMLHttpRequest usage here",
        "see xmlhttprequest usage here",
        "call require (os) now",
        "call fetch (url) now",
        "call eval (x) now",
        "call exec (x) now",
    ):
        s = _spec(f"g11-l2-{abs(hash(bad)) % 99999}", description=f"see {bad}")
        okb, _, errsb, _ = v.validate(s)
        assert not okb, bad
        assert any("unsafe-directive" in e for e in errsb), (bad, errsb)


@pytest.mark.skip(
    reason=(
        "G11-L1 DEFERRED: Registry.register(trust=TRUSTED) still accepts any "
        "in-process caller/spec whose provenance dict self-claims "
        "source=='official', and load_official_registry() confers TRUSTED on "
        "any YAML file in the loaded directory that claims it — the string "
        "check authenticates nothing. A real fix needs loader-context "
        "authentication (pinned directory + digest pinning) or a private "
        "TRUSTED-conferral path, which requires changing library.py/official.py "
        "callers outside this fix's exclusive write scope "
        "(registry.py+validator.py+tests only). Downgrading unilaterally in "
        "registry.py would break the official builders; so this is "
        "documented here as a counted skip, not hidden."
    )
)
def test_g11_l1_trusted_requires_authenticated_provenance():
    raise AssertionError("deferred: see skip reason")


# ---------------- YAML + schema ----------------

def test_yaml_normalize_schema_crosscheck():
    text = Path("templates/reports/REPORT-TEMPLATE.yaml").read_text()
    import yaml

    doc = yaml.safe_load(text)
    flat = normalize_template_dict({"report_template": doc.get("report_template", doc), "sections": [], "finding_fields": [], "section_order": [], "provenance": {}})
    assert flat["template_id"]
    schema = json.loads(Path("docs/schemas/report-template.schema.json").read_text())
    good = _spec()
    validate_against_schema(json.loads(json.dumps(good.model_dump(mode="json"))), schema)
    bad = dict(json.loads(json.dumps(good.model_dump(mode="json"))), template_id="Bad_ID")
    with pytest.raises(TemplateError):
        validate_against_schema(bad, schema)
    # malformed YAML
    with pytest.raises(TemplateError):
        spec_from_yaml_text("report_template: [unclosed")


def test_official_library_loads_20_trusted():
    reg = load_official_registry(str(OFFICIAL_DIR))
    specs = reg.list()
    assert len(specs) == 20
    ids = sorted(s.template_id for s in specs)
    for expected in ["security-audit", "executive-security", "developer-security", "web-app-security", "api-security", "supabase-security", "dependency-security", "supply-chain-security", "ai-security", "mcp-security", "threat-model", "pre-release-security", "regression-security", "authentication-security", "authorization-security", "database-security", "business-logic-security", "cloud-security", "container-security", "agent-security"]:
        assert expected in ids, expected
    v = ReportTemplateValidator()
    schema = json.loads(Path("docs/schemas/report-template.schema.json").read_text())
    for s in specs:
        ok, trust, _, _ = v.validate(s)
        assert ok, s.template_id
        # POST-T020 R2: validator stays UNTRUSTED (advisory); stored trust
        # is conferred by the loader via Registry.register(trust=TRUSTED).
        assert trust == TemplateTrust.UNTRUSTED
        assert reg.trust_of(s.template_id, s.version) == TemplateTrust.TRUSTED
        validate_against_schema(json.loads(json.dumps(s.model_dump(mode="json"))), schema)
    # deterministic digests
    d1 = {s.template_id: ResolvedReportTemplate.digest_of(s) for s in specs}
    reg2 = load_official_registry(str(OFFICIAL_DIR))
    d2 = {s.template_id: ResolvedReportTemplate.digest_of(s) for s in reg2.list()}
    assert d1 == d2


# ---------------- resolver + service ----------------

def test_resolver_by_id_tasktype_objective_unknown():
    reg = load_official_registry(str(OFFICIAL_DIR))
    r = ReportTemplateResolver(reg)
    assert r.resolve(template_id="api-security").template_id == "api-security"
    assert r.resolve(task_type="threat_model").template_id == "threat-model"
    assert r.resolve(task_type="audit").template_id == "security-audit"
    assert r.resolve(objective="quarterly executive briefing for board").template_id == "executive-security"
    assert r.resolve(objective="scan supabase RLS policies").template_id == "supabase-security"
    with pytest.raises(TemplateError) as e:
        r.resolve(template_id="nope")
    assert e.value.code == TemplateErrorCode.NOT_FOUND
    svc = ReportTemplateService(reg)
    assert svc.plan(template_id="mcp-security").template_id == "mcp-security"


# ---------------- composition ----------------

def test_composition_add_only_and_weaken_denied():
    from emo_cyber_agent.report_templates.library import _compose

    base = _spec("base-x")
    child = _spec("child-x", finding_fields=["finding.finding_id", "finding.title", "finding.severity", "finding.confidence", "finding.status", "finding.evidence_ids", "finding.verification_ids", "finding.provenance", "finding.remediation"], sections=({"name": "findings", "fields": ["finding.remediation"]},))
    composed = _compose(base, child)
    assert "finding.remediation" in composed.finding_fields
    weak = _spec("weak-x", preserve_provenance=False, redact_secrets=True, deterministic=True)
    # bypass pydantic-level: construct via model_construct to simulate hostile child
    hostile = base.model_copy(update={"preserve_provenance": False})
    with pytest.raises(TemplateError) as e:
        _compose(base, hostile)
    assert e.value.code == TemplateErrorCode.COMPOSITION_INVALID
    small_base = _spec("small-base", finding_fields=["finding.title"])
    small_child = _spec("small-child", finding_fields=["finding.severity"])
    with pytest.raises(TemplateError) as e2:
        _compose(small_base, small_child)
    assert e2.value.code == TemplateErrorCode.COMPOSITION_INVALID


# ---------------- renderer semantics ----------------

def test_renderer_mandatory_provenance_order_deterministic():
    rep = _report()
    before = rep.model_dump()
    resolved = _resolved(_spec(sections=({"name": "findings", "fields": ["finding.title"]}, {"name": "summary", "fields": []}), section_order=["summary", "findings", "limitations"]))
    pres = apply_report_template(rep, resolved)
    assert [s["name"] for s in pres["sections"]][:2] == ["summary", "findings"]
    findings = next(s["findings"] for s in pres["sections"] if s["name"] == "findings")
    for entry in findings:
        for mandatory in ["finding_id", "status", "severity", "confidence", "evidence_ids", "verification_ids", "provenance"]:
            assert mandatory in entry, mandatory
        assert entry["provenance"] == {"candidate": "c1", "rule": "R1"}
    assert rep.model_dump() == before  # source report untouched
    assert apply_report_template(rep, resolved) == apply_report_template(rep, resolved)
    body = json.loads(to_canonical_json_with_template(rep, resolved))
    assert body["template_id"] == "demo-report"
    md = to_markdown_with_template(rep, resolved)
    assert "Template:" in md and "f1" in md


def test_renderer_visibility_redaction_nonreportable_format_gate():
    rep = _report()
    vis_spec = _spec(
        "vis-r", sections=({"name": "summary", "fields": []}, {"name": "findings", "fields": ["finding.title"], "visibility": [{"show_if_field": "finding.severity", "operator": "==", "value": "critical"}]}),
        section_order=["summary", "findings", "limitations"],
    )
    pres = apply_report_template(rep, _resolved(vis_spec))
    assert "findings" not in [s["name"] for s in pres["sections"]]  # no critical in fixture
    # redaction: secrets never leak raw
    evil = _finding("evil", audit="A")
    evil = evil.model_copy(update={"title": "key ghp_LIVE999 here"})
    rep2 = build_report(audit_id="A", findings=[evil], generated_at="2026-01-01T00:00:00+00:00")
    md2 = to_markdown_with_template(rep2, _resolved())
    assert "ghp_LIVE999" not in md2
    # non-reportable gating
    suppressed = _finding("sup", audit="A", status="suppressed")
    rep3 = build_report(audit_id="A", findings=[suppressed], include_non_reportable=True, generated_at="2026-01-01T00:00:00+00:00")
    assert apply_report_template(rep3, _resolved())["non_reportable"] == []
    allow = _spec("allow-nr", show_non_reportable=True)
    assert len(apply_report_template(rep3, _resolved(allow))["non_reportable"]) == 1
    # format gate
    json_only = _spec("json-only", output_formats=["json"])
    with pytest.raises(Exception):
        to_markdown_with_template(rep, _resolved(json_only))
    # hostile flags denied at render
    hostile = _spec().model_copy(update={"preserve_provenance": False})
    with pytest.raises(Exception):
        apply_report_template(rep, _resolved(hostile))


def test_renderer_no_scores_no_ranking():
    rep = _report()
    out = to_canonical_json_with_template(rep, _resolved())
    assert "security_score" not in out and "risk_score" not in out
    assert "ai_verdict" not in out and "overall_safe" not in out


# ---------------- task integration ----------------

def test_task_template_wiring_override():
    from emo_cyber_agent.skills.builtin.catalog import load_builtin_registry
    from emo_cyber_agent.tasks.registry import TaskRegistry
    from emo_cyber_agent.tasks.resolver import TaskResolver
    from emo_cyber_agent.tasks.service import TaskService
    from emo_cyber_agent.tasks.spec import TaskScope, TaskSpec

    t_reg = TaskRegistry()
    t_reg.register(TaskSpec(task_id="demo-audit", name="D", version="1.0.0", type="audit", objective="answer", scope=TaskScope(included=["repository"], target_types=["repo"]), inputs_required=("source-tree",), required_skills=("injection",), methodology_phases=("reconnaissance",), evidence_required=("file-evidence",), stop_conditions=("done",), acceptance_criteria=("ok",), report_template="security-audit"))
    tpl_reg = load_official_registry(str(OFFICIAL_DIR))
    svc = TaskService(task_registry=t_reg, skill_registry=load_builtin_registry(), template_registry=tpl_reg)
    resolved = svc.plan("demo-audit", project_files=["src/a.py"])
    assert resolved.report_template == "security-audit" and resolved.report_template_known is True
    over = svc.plan("demo-audit", project_files=["src/a.py"], report_template_override="api-security")
    assert over.report_template == "api-security" and over.report_template_known is True
    from emo_cyber_agent.tasks.spec import TaskError as _TE

    with pytest.raises(_TE):
        svc.plan("demo-audit", project_files=["src/a.py"], report_template_override="missing-template")
    # no registry wired → unverified warning, still resolves
    svc2 = TaskService(task_registry=t_reg)
    r2 = svc2.plan("demo-audit", project_files=["src/a.py"])
    assert r2.report_template_known is False
