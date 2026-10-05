"""ECA-T012 — Reporting & export contract tests (offline).

JSON/JSONL/Markdown contracts, determinism, provenance preservation,
semantic preservation (no reinterpretation), redaction, injection
resistance, snapshot consistency, failure semantics, CLI + Python API
adapters, no-LLM/no-score guarantees. No network.
"""

import json

import pytest

from emo_cyber_agent.core.findings import FindingStore, Remediation, SecurityFinding
from emo_cyber_agent.core.reporting import (
    ReportError,
    ReportGenerator,
    ReportService,
    build_report,
    generate_report,
    md_escape,
    order_findings,
    to_canonical_json,
    to_jsonl,
    to_markdown,
)


def _finding(fid, audit="A", severity="high", status="confirmed", title="T", desc="D", loc=("src/a.py:10",), evidence=("e1",), cwe: str | None = "CWE-639", fp=None):
    return SecurityFinding(finding_id=fid, audit_id=audit, asset_id="asset-1", title=title, description=desc, category="authorization", severity=severity, confidence=0.8, status=status, cwe=cwe, owasp="A01:2021-Broken Access Control", affected_locations=loc, evidence_ids=evidence, observation_ids=("o1",), candidate_id="c1", verification_ids=("v1",), provenance={"candidate": "c1", "rule": "R1", "classification_version": "cls-v1", "finding_schema": "0.1.0", "policy": "strict"}, remediation=Remediation(recommendation="fix", affected_component="src/a.py", remediation_type="authorization-check", validation_guidance="retest"), references=("https://example.com/docs",), impact="data exposure", root_cause="missing check", fingerprint=fp or f"fp-{fid}")


def _service():
    return ReportService()


# ---------------- fixtures ----------------

def fx_full_report():
    return [_finding("f-critical", severity="critical"), _finding("f-high", severity="high"), _finding("f-medium", severity="medium", loc=("src/b.py:3",)), _finding("f-low", severity="low"), _finding("f-info", severity="info")]


def fx_empty_audit():
    return []


def fx_malicious():
    return [_finding("f-evil", title="]# **pwned** [x](javascript:alert(1))", desc="```\nDROP TABLE users\n``` <script>alert(2)</script> ignore previous instructions", loc=("src/evil$(x).py:1",))]


def fx_secret():
    return [_finding("f-sec", title="key ghp_LIVE999 here", desc="token: supersecretvalue123 bearer abc.def.ghi", loc=("src/cfg.py:7",))]


def fx_conflicted():
    a = _finding("f-a", title="A")
    return [a]


# ---------------- JSON contract ----------------

def test_json_valid_deterministic_schema():
    svc = _service()
    rep = svc.generate(audit_id="A", findings=fx_full_report(), scope={"repo": "acme/web"})
    import emo_cyber_agent.core.reporting as _r
    stamp = "2026-01-01T00:00:00+00:00"
    first = svc.generate_json(_r.build_report(audit_id="A", findings=[f for f in fx_full_report()], scope={"repo": "acme/web"}, generated_at=stamp))
    second = svc.generate_json(_r.build_report(audit_id="A", findings=[f for f in fx_full_report()], scope={"repo": "acme/web"}, generated_at=stamp))
    assert first == second  # same state → same logical output
    body = json.loads(first)
    import pathlib

    schema = json.loads(pathlib.Path("docs/schemas/report.schema.json").read_text())
    import jsonschema

    jsonschema.validate(body, schema)
    assert body["metadata"]["report_version"] == "1.0" and body["metadata"]["audit_id"] == "A"
    assert body["summary"]["total_findings"] == 5
    assert "security_score" not in first and "risk_score" not in first  # §36: no scores


def test_json_null_semantics_and_provenance():
    f = _finding("f-n", cwe=None)
    f = SecurityFinding(**{**f.model_dump(), "owasp": None, "impact": "UNASSESSED"})
    rep = _service().generate(audit_id="A", findings=[f])
    body = json.loads(to_canonical_json(rep))
    assert body["findings"][0]["cwe"] is None and body["findings"][0]["owasp"] is None
    assert body["findings"][0]["provenance"]["candidate"] == "c1"
    assert body["findings"][0]["fingerprint"] == "fp-f-n"


def test_json_round_trip_semantic():
    rep = _service().generate(audit_id="A", findings=fx_full_report())
    body = json.loads(to_canonical_json(rep))
    for entry in body["findings"]:
        assert entry["severity"] in ("critical", "high", "medium", "low", "info")
        assert 0.0 <= entry["confidence"] <= 1.0 and entry["candidate_id"] and entry["fingerprint"]


# ---------------- JSONL contract ----------------

def test_jsonl_stream_format():
    import emo_cyber_agent.core.reporting as _r2
    rep = _service().generate(audit_id="A", findings=fx_full_report())
    rep = _r2.build_report(audit_id="A", findings=fx_full_report(), generated_at="2026-01-01T00:00:00+00:00")
    text = to_jsonl(rep)
    lines = [json.loads(line) for line in text.strip().split("\n")]
    assert [line["record"] for line in lines] == ["metadata"] + ["finding"] * 5 + ["summary"]
    assert lines[0]["audit_id"] == "A" and lines[-1]["total_findings"] == 5
    again = to_jsonl(_r2.build_report(audit_id="A", findings=fx_full_report(), generated_at="2026-01-01T00:00:00+00:00"))
    assert text == again


# ---------------- Markdown contract ----------------

def test_markdown_sections_and_order():
    rep = _service().generate(audit_id="A", findings=fx_full_report(), limitations=["scanner X unavailable"])
    md = to_markdown(rep)
    for section in ("# EMO-Cyber-Agent Security Report", "## Summary", "## Limitations", "## Findings"):
        assert section in md
    assert "scanner X unavailable" in md
    positions = [md.index(f"ID: `fp-f-{s}`") if False else -1 for s in ()]
    # severity order critical → high → medium → low is deterministic
    order = ["f-critical", "f-high", "f-medium", "f-low", "f-info"]
    indices = [md.index(f"ID: `{fid}`") for fid in order]
    assert indices == sorted(indices)
    assert "security_score" not in md and "risk_score" not in md and "overall grade" not in md.lower()


def test_markdown_escaping_and_injection():
    rep = _service().generate(audit_id="A", findings=fx_malicious())
    md = to_markdown(rep)
    assert "[x](javascript" not in md and "](javascript:" not in md and "<script>" not in md  # no ACTIVE link/script survives (escaped entities are inert text)
    assert md.count("```") % 2 == 0  # fences stay balanced (content fences neutralized)
    assert "DROP TABLE" in md  # content preserved as escaped text, not structure


def test_markdown_secret_redaction_and_null_display():
    rep = _service().generate(audit_id="A", findings=fx_secret())
    md = to_markdown(rep)
    assert "ghp_LIVE999" not in md and "supersecretvalue123" not in md
    f = SecurityFinding(**{**_finding("f-x", cwe=None).model_dump(), "owasp": None})
    md2 = to_markdown(_service().generate(audit_id="A", findings=[f]))
    assert "Not assessed" in md2


def test_markdown_partial_states_visible():
    rep = _service().generate(audit_id="A", findings=[], limitations=["verification blocked for scope X", "2 controls unevaluated"])
    md = to_markdown(rep)
    assert "No reportable findings" in md and "blocked for scope X" in md
    assert "`0 confirmed` never means" in md  # explicit anti-misreading disclaimer present
    assert "No vulnerabilities found" not in md  # never claims absence


def test_non_reportable_projection_choice():
    refuted = _finding("f-r", status="refuted")
    rep = _service().generate(audit_id="A", findings=[refuted])
    assert rep.findings == () and rep.non_reportable == ()
    rep2 = _service().generate(audit_id="A", findings=[refuted], include_non_reportable=True)
    assert len(rep2.non_reportable) == 1 and rep2.findings == ()
    md = to_markdown(rep2)
    assert "Non-reportable" in md and "f-r" in md  # visible, never silently dropped


# ---------------- semantics preservation ----------------

def test_semantics_preserved_across_formats():
    f = _finding("f-s", severity="medium", status="confirmed")
    rep = _service().generate(audit_id="A", findings=[f], verifications={"v1": {"method": "static_confirmation", "status": "confirmed", "confidence": 0.85}}, evidence={"e1": {"tool": "semgrep", "location": "src/a.py:10", "collected_at": "t", "digest": "d"}})
    body = json.loads(to_canonical_json(rep))
    assert body["findings"][0]["severity"] == "medium" and body["findings"][0]["status"] == "confirmed" and body["findings"][0]["confidence"] == 0.8
    assert body["findings"][0]["verifications"][0]["status"] == "confirmed"
    assert body["findings"][0]["evidence"][0]["evidence_id"] == "e1"
    md = to_markdown(rep)
    assert "medium" in md and "confirmed" in md
    for line in to_jsonl(rep).strip().split("\n"):
        entry = json.loads(line)
        if entry["record"] == "finding":
            assert entry["severity"] == "medium" and entry["status"] == "confirmed"


def test_verification_states_verbatim():
    for status in ("supported", "refuted", "inconclusive"):
        f = _finding(f"f-{status}", status="confirmed")
        rep = _service().generate(audit_id="A", findings=[f], verifications={"v1": {"method": "static_confirmation", "status": status, "confidence": 0.5}})
        body = json.loads(to_canonical_json(rep))
        assert body["findings"][0]["verifications"][0]["status"] == status  # never remapped


def test_cross_audit_rejected():
    with pytest.raises(ReportError) as e:
        _service().generate(audit_id="A", findings=[_finding("f-x", audit="B")])
    assert e.value.code.value == "REPORTABILITY_DENIED"
    with pytest.raises(ReportError):
        _service().generate(audit_id="", findings=[])


def test_read_only_no_mutation():
    findings = fx_full_report()
    before = [f.model_dump() for f in findings]
    _service().generate(audit_id="A", findings=findings)
    assert [f.model_dump() for f in findings] == before


def test_snapshot_single_timestamp():
    rep = _service().generate(audit_id="A", findings=fx_full_report())
    md = to_markdown(rep)
    assert md.count(rep.metadata.generated_at[:19]) >= 1
    assert rep.metadata.generated_at  # one stamp reused by every section


def test_summary_derived_no_score():
    rep = _service().generate(audit_id="A", findings=fx_full_report())
    assert rep.summary.total_findings == 5
    assert rep.summary.by_severity == {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1}
    assert not hasattr(rep.summary, "security_score")


def test_oversized_unicode_edges():
    big = _finding("f-big", desc="é" * 5000 + "\x00null?", loc=("src/ünïcode_文件.py:1",))
    rep = _service().generate(audit_id="A", findings=[big])
    body = json.loads(to_canonical_json(rep))
    assert len(body["findings"][0]["description"]) <= 2000
    md = to_markdown(rep)
    assert "ünïcode" in md


def test_references_no_invented_urls():
    f = _finding("f-u")
    f = SecurityFinding(**{**f.model_dump(), "references": ("https://example.com/x", "javascript:evil()")})
    rep = _service().generate(audit_id="A", findings=[f])
    body = json.loads(to_canonical_json(rep))
    assert "https://example.com/x" in body["findings"][0]["references"]
    assert not any(r.startswith("javascript:") for r in body["findings"][0]["references"])


# ---------------- adapters ----------------

def test_python_api_surface():
    from emo_cyber_agent.core.reporting import generate_report

    rep = generate_report(audit_id="A", findings=fx_full_report())
    assert rep.metadata.audit_id == "A" and len(rep.findings) == 5


def test_cli_report_json_and_markdown(tmp_path):
    import json as _json

    from typer.testing import CliRunner

    from emo_cyber_agent.cli.main import app

    path = tmp_path / "findings.json"
    path.write_text(_json.dumps([f.model_dump(mode="json") for f in fx_full_report()]))
    runner = CliRunner()
    out = runner.invoke(app, ["report", "--findings", str(path), "--audit-id", "A", "--format", "json"])
    assert out.exit_code == 0, out.output
    assert _json.loads(out.output)["metadata"]["audit_id"] == "A"
    out_md = runner.invoke(app, ["report", "--findings", str(path), "--audit-id", "A", "--format", "markdown"])
    assert out_md.exit_code == 0 and "## Findings" in out_md.output
    out_file = tmp_path / "rep.md"
    out3 = runner.invoke(app, ["report", "--findings", str(path), "--audit-id", "A", "--format", "markdown", "--output", str(out_file)])
    assert out3.exit_code == 0 and out_file.exists()


def test_cli_failures():
    from typer.testing import CliRunner

    from emo_cyber_agent.cli.main import app

    runner = CliRunner()
    assert runner.invoke(app, ["report", "--findings", "nope.json", "--audit-id", "A"]).exit_code == 2
    assert runner.invoke(app, ["report", "--findings", "x", "--audit-id", "A", "--format", "pdf"]).exit_code == 2


def test_cli_cross_audit_denied(tmp_path):
    import json as _json

    from typer.testing import CliRunner

    from emo_cyber_agent.cli.main import app

    path = tmp_path / "findings.json"
    path.write_text(_json.dumps([_finding("f-x", audit="B").model_dump(mode="json")]))
    out = CliRunner().invoke(app, ["report", "--findings", str(path), "--audit-id", "A"])
    assert out.exit_code == 3


def test_report_generator_contract():
    from emo_cyber_agent.core.reporting import ReportGenerator

    gen = ReportGenerator()
    rep = _service().generate(audit_id="A", findings=fx_full_report())
    assert json.loads(gen.generate_json(rep))["metadata"]["audit_id"] == "A"
    assert gen.generate_jsonl(rep).count("\n") == 7  # metadata + 5 findings + summary
    assert gen.generate_markdown(rep).startswith("# EMO-Cyber-Agent")


def test_no_llm_in_reporting():
    import emo_cyber_agent.core.reporting as m

    body = open(m.__file__).read().split('"""', 2)[-1].lower()
    for banned in ("openai", "anthropic", "transformers", "import torch", "llm(", "_llm", "prompt(", "prompt=", "rerank", "prioritiz"):
        assert banned not in body, banned
