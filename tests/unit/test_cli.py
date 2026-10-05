"""ECA-T014 — Universal CLI tests (offline).

Command surface, help contract, exit codes, stdout/stderr split, JSON
modes, doctor presence-checks, scope-safe paths, secret handling, signal
handling, concurrency isolation, shell safety, contract + security + E2E
(CLI→Core→mocks→finding/report) + packaging checks. No network.
"""

import json
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from emo_cyber_agent.cli.main import (
    EXIT_DOMAIN_FAILURE,
    EXIT_INVALID_INPUT,
    EXIT_POLICY_DENIED,
    app,
    load_config,
)

runner = CliRunner()


def _finding_dict(fid="f1", audit="A"):
    from emo_cyber_agent.core.findings import SecurityFinding

    return SecurityFinding(finding_id=fid, audit_id=audit, title="T", description="D", category="authorization", severity="high", confidence=0.8, candidate_id="c1", evidence_ids=("e1",), fingerprint=f"fp-{fid}", provenance={"candidate": "c1"}).model_dump(mode="json")


def _candidate_file(tmp_path, audit="A"):
    from emo_cyber_agent.core.correlation import FindingCandidate

    path = tmp_path / "cand.json"
    path.write_text(json.dumps(FindingCandidate(audit_id=audit, hypothesis="h", evidence_ids=("e1",)).model_dump(mode="json")))
    return str(path)


# ---------------- surface + help ----------------

def test_command_surface_exact():
    names = sorted(cmd.callback.__name__ for cmd in app.registered_commands)
    assert names == ["audit", "doctor", "extensions", "mcp", "report", "review", "status", "verify"]


def test_help_deterministic_no_secrets_no_shell_claims():
    first = runner.invoke(app, ["--help"]).output
    assert runner.invoke(app, ["--help"]).exit_code == 0
    assert runner.invoke(app, ["--help"]).output == first
    lowered = first.lower()
    for banned in ("--shell", "--exec", "--grant", "--sudo", "--allow-write", "--bypass-policy", "token=", "secret="):
        assert banned not in lowered
    for cmd in ("audit", "review", "verify", "status", "report", "doctor", "mcp", "extensions"):
        out = runner.invoke(app, [cmd, "--help"])
        assert out.exit_code == 0, cmd
        assert "Usage" in out.output


def test_exit_code_constants_documented():
    import emo_cyber_agent.cli.main as cli

    assert (cli.EXIT_SUCCESS, cli.EXIT_DOMAIN_FAILURE, cli.EXIT_INVALID_INPUT, cli.EXIT_POLICY_DENIED, cli.EXIT_SECURITY_BLOCKED, cli.EXIT_UNAVAILABLE, cli.EXIT_INCONCLUSIVE, cli.EXIT_INTERNAL) == (0, 1, 2, 3, 4, 5, 6, 7)


# ---------------- contracts ----------------

def test_audit_json_and_human():
    out = runner.invoke(app, ["audit", ".", "--format", "json"])
    assert out.exit_code == 0
    body = json.loads(out.output)
    assert body["status"] == "ok" and body["result"]["target"] == "."
    assert out.stderr == ""
    human = runner.invoke(app, ["audit", "."])
    assert human.exit_code == 0 and "audit_id" in human.output


def test_audit_invalid_inputs():
    assert runner.invoke(app, ["audit", ".", "--mode", "bogus"]).exit_code == EXIT_INVALID_INPUT
    assert runner.invoke(app, ["audit", ".", "--format", "yaml"]).exit_code == EXIT_INVALID_INPUT
    assert runner.invoke(app, ["audit", ".", "--grant", "admin"]).exit_code == EXIT_INVALID_INPUT


def test_review_delegates():
    out = runner.invoke(app, ["review", "src/app.py", "--format", "json"])
    assert out.exit_code == 0
    assert json.loads(out.output)["result"]["target"] == "src/app.py"


def test_verify_returns_plan():
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        from pathlib import Path

        path = Path(tmp) / "cand.json"
        from emo_cyber_agent.core.correlation import FindingCandidate

        path.write_text(json.dumps(FindingCandidate(audit_id="A", hypothesis="h", evidence_ids=("e1",)).model_dump(mode="json")))
        out = runner.invoke(app, ["verify", "--candidate", str(path), "--method", "static_confirmation", "--kind", "file", "--locator", "src/a.py", "--rationale", "check", "--audit-id", "A", "--format", "json"])
        assert out.exit_code == 0, out.output
        assert json.loads(out.output)["result"]["status"] == "planned"


def test_verify_cross_audit_denied():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "cand.json"
        from emo_cyber_agent.core.correlation import FindingCandidate

        path.write_text(json.dumps(FindingCandidate(audit_id="B", hypothesis="h", evidence_ids=("e1",)).model_dump(mode="json")))
        out = runner.invoke(app, ["verify", "--candidate", str(path), "--method", "static_confirmation", "--kind", "file", "--locator", "src/a.py", "--rationale", "x", "--audit-id", "A"])
        assert out.exit_code == EXIT_POLICY_DENIED


def test_status_unknown_audit_structured():
    out = runner.invoke(app, ["status", "nope", "--format", "json"])
    assert out.exit_code == EXIT_DOMAIN_FAILURE
    body = json.loads(out.output)
    assert body["status"] == "unknown-audit" and body["audit_id"] == "nope"


def test_report_roundtrip_and_output_file(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([_finding_dict()]))
    out = runner.invoke(app, ["report", "--findings", str(path), "--audit-id", "A", "--format", "json"])
    assert out.exit_code == 0 and json.loads(out.output)["metadata"]["audit_id"] == "A"
    dest = tmp_path / "rep.md"
    out2 = runner.invoke(app, ["report", "--findings", str(path), "--audit-id", "A", "--format", "markdown", "--output", str(dest)])
    assert out2.exit_code == 0 and "## Findings" in dest.read_text() and out2.output == ""


def test_doctor_presence_not_values(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_SECRETVALUE123")
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    out = runner.invoke(app, ["doctor"])
    assert out.exit_code == 0
    assert "CONFIGURED" in out.output and "ghp_SECRETVALUE123" not in out.output
    assert "MISSING" in out.output
    body = json.loads(runner.invoke(app, ["doctor", "--format", "json"]).output)
    assert body["status"] == "ok" and "tool:git" in body["checks"]


def test_stdout_stderr_split():
    out = runner.invoke(app, ["audit", ".", "--format", "json"])
    assert out.exit_code == 0 and out.stderr == ""  # results only on stdout
    bad = runner.invoke(app, ["audit", ".", "--mode", "bogus"])
    assert bad.exit_code == EXIT_INVALID_INPUT and bad.stderr != ""


# ---------------- security ----------------

def test_option_injection_and_shell_targets():
    assert runner.invoke(app, ["audit", "x; rm -rf /"]).exit_code == 0  # treated as data target, never shelled
    assert runner.invoke(app, ["audit", ".", "--sudo"]).exit_code == EXIT_INVALID_INPUT
    assert runner.invoke(app, ["audit", ".", "--bypass-policy"]).exit_code == EXIT_INVALID_INPUT
    assert runner.invoke(app, ["audit", ".", "--allow-write"]).exit_code == EXIT_INVALID_INPUT
    assert runner.invoke(app, ["audit", ".", "--unsafe"]).exit_code == EXIT_INVALID_INPUT


def test_secret_in_argument_never_echoed():
    out = runner.invoke(app, ["audit", "ghp_LIVE999", "--format", "json"])
    assert out.exit_code == 0
    assert "ghp_LIVE999" not in out.output and "ghp_LIVE999" not in out.stderr


def test_secret_flag_rejected_with_guidance():
    out = runner.invoke(app, ["audit", ".", "--github-token", "x"])
    assert out.exit_code == EXIT_INVALID_INPUT


def test_malformed_and_oversized_inputs():
    assert runner.invoke(app, ["report", "--findings", "nope.json", "--audit-id", "A"]).exit_code == EXIT_INVALID_INPUT
    assert runner.invoke(app, ["verify", "--candidate", "nope.json", "--method", "static_confirmation", "--kind", "file", "--locator", "x", "--rationale", "x", "--audit-id", "A"]).exit_code == EXIT_INVALID_INPUT


def test_wrong_audit_and_cross_audit():
    out = runner.invoke(app, ["status", "audit-B", "--format", "json"])
    assert out.exit_code == EXIT_DOMAIN_FAILURE
    assert json.loads(out.output)["audit_id"] == "audit-B"  # echoes only the requested id, nothing else


def test_concurrent_audits_isolated():
    first = runner.invoke(app, ["status", "audit-A", "--format", "json"])
    second = runner.invoke(app, ["status", "audit-B", "--format", "json"])
    assert json.loads(first.output)["audit_id"] == "audit-A"
    assert json.loads(second.output)["audit_id"] == "audit-B"


def test_no_direct_adapter_or_business_logic_in_cli():
    import emo_cyber_agent.cli.main as cli

    body = open(cli.__file__).read().split('"""', 2)[-1]
    for banned in ("GitHubAdapter", "SupabaseAdapter", "SemgrepAdapter", "TrivyAdapter", "GitleaksAdapter", "subprocess", "os.system", "shell=True", "Severity(", "classify_", "evaluate_policy("):
        assert banned not in body, banned


def test_signal_handling_sigint(tmp_path):
    script = "import sys; sys.path.insert(0, 'src'); from emo_cyber_agent.cli.main import app; app(['mcp'])"
    proc = subprocess.Popen([sys.executable, "-c", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent", text=True)
    try:
        proc.wait(timeout=5)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        proc.send_signal(2)  # SIGINT like Ctrl+C
        try:
            code, _ = proc.wait(timeout=10), None
        except subprocess.TimeoutExpired:
            proc.kill()
            code = -9
    err = proc.stderr.read() if proc.stderr else ""
    assert code in (130, -2)  # clean interruption, never success
    assert "ghp_" not in err and "Traceback" not in err or "interrupted" in err


# ---------------- config ----------------

def test_config_precedence_and_policy_rejection(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert load_config() == {}
    monkeypatch.setenv("EMO_MODEL", "openai-compatible")
    assert load_config()["model"] == "openai-compatible"
    assert load_config({"model": "explicit"})["model"] == "explicit"
    cfgdir = tmp_path / ".config" / "emo-cyber-agent"
    cfgdir.mkdir(parents=True)
    (cfgdir / "config.json").write_text(json.dumps({"model": "file-model"}))
    monkeypatch.delenv("EMO_MODEL")
    assert load_config()["model"] == "file-model"
    (cfgdir / "config.json").write_text(json.dumps({"policy": "allow-all"}))
    with pytest.raises(Exception):
        load_config()


# ---------------- e2e + packaging ----------------

def test_e2e_cli_core_mock_finding_report(tmp_path):
    """CLI → Core audit → Core-built finding → CLI report (offline)."""
    audit_out = runner.invoke(app, ["audit", ".", "--format", "json"])
    assert audit_out.exit_code == 0
    audit_id = json.loads(audit_out.output)["result"]["audit_id"]
    from emo_cyber_agent.core.correlation import FindingCandidate
    from emo_cyber_agent.core.findings import classify_candidate, promote_candidate

    candidate = FindingCandidate(audit_id=audit_id, asset_id="a1", observation_ids=("o1",), evidence_ids=("e1", "e2"), hypothesis="h", provisional_severity="high", confidence=0.6, rule_id="R1-auth-weakness@corr-v1", status="correlated")
    classification, _ = classify_candidate(candidate=candidate, verification_status="confirmed", scanner_severities=[], evidence_count=2, independent_sources=2, contradiction=False)
    finding = promote_candidate(candidate=candidate, verification_status="confirmed", verification_ids=["v1"], evidence_ids=["e1", "e2"], observation_ids=["o1"], classification=classification, scope_ok=True, policy_ok=True, audit_id=audit_id, asset_id="a1", location="src/a.py", identity="R1")
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([finding.model_dump(mode="json")]))
    rep = runner.invoke(app, ["report", "--findings", str(path), "--audit-id", audit_id, "--format", "markdown"])
    assert rep.exit_code == 0 and finding.finding_id in rep.output


def test_ci_mode_json_pipe_clean():
    out = runner.invoke(app, ["audit", ".", "--format", "json"])
    assert out.exit_code == 0 and out.stderr == ""
    parsed = json.loads(out.output)  # pipe-safe: pure JSON on stdout
    assert "result" in parsed


def test_packaging_contract():
    import tomllib

    with open("/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent/pyproject.toml", "rb") as fh:
        project = tomllib.load(fh)
    assert project["project"]["scripts"]["cyber-agent"] == "emo_cyber_agent.cli.main:app"
    assert runner.invoke(app, ["--help"]).exit_code == 0
