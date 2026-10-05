"""ECA-T016 — H. Release smoke tests.

One canonical case per surface (Python API, CLI, MCP) plus one
extension case, all against the INSTALLED artifact. Detailed behavior
stays with the owner suites (POST-RC-013 parity, POST-RC-014
adversarial, adapter contracts); the gate only proves the previously
validated behavior arrived intact in the install.
"""

from __future__ import annotations

import json
import os
import subprocess


from conftest import ROOT, VERSION, run_console_script, run_installed

SMOKE_API = r"""
import asyncio, json
from emo_cyber_agent import SecurityAuditor, ReportService, generate_report
from emo_cyber_agent.core.correlation import FindingCandidate
from emo_cyber_agent.core.findings import SecurityFinding
from emo_cyber_agent.core.service import FoundationSecurityAuditor

async def main():
    assert issubclass(FoundationSecurityAuditor, SecurityAuditor)
    auditor = FoundationSecurityAuditor()
    result = await auditor.audit(target='PROBE_TARGET', mode='quick', permission_profile='read_only')
    assert result.status in ('completed', 'pending', 'planned', 'stub', 'created'), result.status
    doctor = await auditor.doctor()
    assert isinstance(doctor, dict) and doctor, 'doctor must return a mapping'
    from emo_cyber_agent.skills.builtin import load_builtin_registry
    from emo_cyber_agent.skills.resolver import SkillResolver
    resolved = SkillResolver(load_builtin_registry()).resolve(files=['app.py', 'requirements.txt'], objective='review')
    assert isinstance(resolved, list)
    from emo_cyber_agent.core.resources import official_catalog_path
    from emo_cyber_agent.tools.packs.catalog import load_official_tool_packs
    packs = load_official_tool_packs(official_catalog_path() / 'tools' / 'packs' / 'official')
    assert len(packs.list()) == 4
    from emo_cyber_agent.threat_modeling.methods import get_method, registered_methods
    assert 'stride' in registered_methods() and get_method('stride').method_id == 'stride'
    from emo_cyber_agent.adapters.mock_verification import MockVerificationProvider
    from emo_cyber_agent.core.policy import StrictPolicyEngine
    from emo_cyber_agent.core.tool_registry import ToolRegistry
    from emo_cyber_agent.core.verification import VerificationRequest, VerificationService, VerificationBudget, get_verification_tool_specs
    from emo_cyber_agent.core.correlation import EvidenceStore
    _registry = ToolRegistry()
    for _spec in get_verification_tool_specs():
        _registry.register(_spec)
    svc = VerificationService(executor=MockVerificationProvider('SUPPORTED'), policy=StrictPolicyEngine(), registry=_registry, store=EvidenceStore(), scope_allows=lambda a, t: True, profile='read_only', budget=VerificationBudget())
    cand = FindingCandidate(audit_id='SMOKE', hypothesis='h', evidence_ids=('e1',))
    plan = svc.plan(candidate=cand, request=VerificationRequest(method='static_confirmation', target={'kind': 'file', 'locator': 'src/a.py'}, rationale_summary='smoke'), audit_id='SMOKE')
    assert plan.plan_id
    service = ReportService()
    rep = service.generate(audit_id='SMOKE', findings=[])
    text = service.generate_json(rep)
    assert text
    print(json.dumps({'audit_status': result.status, 'plan_id': plan.plan_id, 'report_ok': True}))

asyncio.run(main())
"""


def test_python_api_smoke_from_installed_package(venv, tmp_path):
    """Canonical Python API case: audit, doctor, skills, packs, threat
    model, verification plan, report — public APIs only."""
    target = tmp_path / "probe"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    code = SMOKE_API.replace("PROBE_TARGET", str(target))
    proc = run_installed(venv / "bin" / "python", ["-c", code], cwd=tmp_path)
    body = json.loads(proc.stdout.strip().splitlines()[-1])
    assert body["report_ok"] is True and body["plan_id"]


def test_public_api_surface_tiers():
    import emo_cyber_agent as pkg

    assert set(pkg.__all__) == set(pkg.SUPPORTED_API)
    for name in pkg.SUPPORTED_API:
        assert getattr(pkg, name, None) is not None, name
    from emo_cyber_agent.core.correlation import EvidenceStore
    from emo_cyber_agent.core.findings import SecurityFinding
    from emo_cyber_agent.core.reasoning import ReasoningEngine
    from emo_cyber_agent.core.reporting import AuditReport
    from emo_cyber_agent.core.verification import VerificationService

    assert all([ReasoningEngine, VerificationService, EvidenceStore, SecurityFinding, AuditReport])
    for internal in ("ToolRegistry", "StrictPolicyEngine", "EvidenceItem", "ToolExecutor"):
        assert not hasattr(pkg, internal), internal


def test_import_safety_no_side_effects():
    import subprocess as _sp
    import sys as _sys

    code = (
        "import sys, threading, json;"
        "before_threads = threading.active_count();"
        "import emo_cyber_agent as m;"
        "from emo_cyber_agent import ReportService;"
        "print(json.dumps({'version': m.__version__, 'threads_delta': threading.active_count() - before_threads, 'api': sorted(m.__all__)}))"
    )
    import os as _os

    env = dict(_os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + (_os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    proc = _sp.run(
        [_sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
        env=env,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    body = json.loads(proc.stdout)
    assert body["version"] == VERSION and body["threads_delta"] == 0
    assert "SecurityAuditor" in body["api"]


def test_cli_smoke_from_installed_package(venv, tmp_path):
    """Canonical CLI case: doctor, status, audit, verify, extensions —
    exit codes, stdout/stderr split, JSON validity."""
    target = tmp_path / "probe"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")

    doctor = run_console_script(venv, ["doctor", "--format", "json"], cwd=tmp_path)
    assert doctor.returncode == 0
    assert json.loads(doctor.stdout)["status"] == "ok"

    status = run_console_script(venv, ["status", "nope", "--format", "json"], cwd=tmp_path, check=False)
    assert status.returncode == 1  # EXIT_DOMAIN_FAILURE, never another audit's data
    assert json.loads(status.stdout)["status"] == "unknown-audit"

    audit = run_console_script(
        venv, ["audit", str(target), "--mode", "quick", "--format", "json"], cwd=tmp_path
    )
    assert audit.returncode == 0
    assert json.loads(audit.stdout)["status"] == "ok"

    candidate = tmp_path / "cand.json"
    candidate.write_text(
        json.dumps({"audit_id": "SMOKE", "hypothesis": "h", "evidence_ids": ["e1"]}),
        encoding="utf-8",
    )
    verify = run_console_script(
        venv,
        ["verify", "--candidate", str(candidate), "--method", "static_confirmation",
         "--kind", "file", "--locator", "src/a.py", "--rationale", "smoke",
         "--audit-id", "SMOKE", "--format", "json"],
        cwd=tmp_path,
    )
    assert verify.returncode == 0
    assert json.loads(verify.stdout)["result"]["status"] == "planned"

    extensions = run_console_script(venv, ["extensions", "--action", "list", "--format", "json"], cwd=tmp_path)
    assert extensions.returncode == 0
    body = json.loads(extensions.stdout)
    assert body["code_load"] == "disabled"

    # stdout is machine-consumable, stderr carries no secrets
    for proc in (doctor, audit, verify, extensions):
        assert "ghp_" not in proc.stdout + proc.stderr
        assert "AKIA" not in proc.stdout + proc.stderr


def _mcp_session(executable: list[str], payloads: list[str], timeout: int = 120) -> tuple[int, list[str]]:
    """Drive the real stdio server: send lines, close stdin, collect lines."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        executable,
        input="\n".join(payloads) + "\n",
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd="/tmp",
        env=env,
    )
    return proc.returncode, [line for line in proc.stdout.splitlines() if line.strip()]


def test_mcp_real_stdio_smoke_from_installed_package(venv_mcp):
    """Canonical MCP case over real stdio: initialize, list, call,
    ping, malformed line, unknown method, bad args, oversized line, EOF."""
    big = "x" * (1024 * 1024 + 16)
    payloads = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cyber_status", "arguments": {}}}),
        json.dumps({"jsonrpc": "2.0", "id": 4, "method": "ping"}),
        "{not-json",
        json.dumps({"jsonrpc": "2.0", "id": 6, "method": "nope/unknown"}),
        json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "cyber_extensions", "arguments": {"action": "install"}}}),
        json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "cyber_status", "arguments": {}, "pad": big}}),
    ]
    code, lines = _mcp_session([str(venv_mcp / "bin" / "cyber-agent"), "mcp"], payloads)
    assert code == 0, "server must exit cleanly on EOF"
    by_id = {}
    for line in lines:
        body = json.loads(line)
        if "id" in body:
            by_id[body["id"]] = body
    # initialize negotiates the server identity
    assert by_id[1]["result"]["serverInfo"] == {"name": "emo-cyber-agent", "version": VERSION}
    # six tools, exactly the documented surface
    tools = [t["name"] for t in by_id[2]["result"]["tools"]]
    assert tools == ["cyber_audit", "cyber_review", "cyber_verify", "cyber_report", "cyber_status", "cyber_extensions"]
    # status call succeeds: inner content payload carries status ok (no protocol error)
    assert "error" not in by_id[3]
    status_payload = json.loads(by_id[3]["result"]["content"][0]["text"])
    assert status_payload["status"] == "ok"
    assert status_payload["tool"] == "cyber_status"
    assert status_payload["result"]["version"] == VERSION
    # ping answers
    assert by_id[4]["result"] == {}
    # malformed line gets a parse-error envelope and the server survives
    assert by_id.get("None") is None
    parse_errors = [json.loads(line) for line in lines if '"id": null' in line]
    assert parse_errors and parse_errors[0]["error"]["code"] == -32700
    # unknown method is protocol-correct
    assert by_id[6]["error"]["code"] == -32601
    # hostile tool arguments fail closed at the protocol layer
    assert by_id[7]["error"]["code"] == -32602
    # oversized line is dropped without a response, server still exits 0
    assert 8 not in by_id


def test_extension_smoke_from_installed_package(venv, tmp_path):
    """Canonical extension case from the install: official content
    discovers, third-party content validates, hostile content rejects —
    with installation alone granting no trust."""
    import shutil as _shutil

    ext_root = tmp_path / "ext-root"
    _shutil.copytree(ROOT / "tests" / "fixtures" / "extensions", ext_root)
    code = (
        "from emo_cyber_agent.extensions import read_extensions;"
        "import json;"
        f"root = {str(ext_root)!r};"
        "listed = read_extensions('list', extra_roots=(root,));"
        "desc = read_extensions('describe', extension_id='malicious-third-party', extra_roots=(root,));"
        "official = read_extensions('describe', extension_id='official-skill-pack', extra_roots=(root,));"
        "print(json.dumps({"
        "'code_load': listed['code_load'],"
        "'discovered': listed['discovered'],"
        "'malicious_trust': desc['extension']['trust'],"
        "'malicious_registered': desc['extension']['registered'],"
        "'official_trust': official['extension']['trust']['state'],"
        "}))"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code], cwd=tmp_path)
    body = json.loads(proc.stdout.strip().splitlines()[-1])
    assert body["code_load"] == "disabled"
    assert body["discovered"] == 17
    assert body["malicious_trust"] == "rejected"
    assert body["malicious_registered"] is False
    # installation does not trust: official content under an extra (third-party) root stays untrusted
    assert body["official_trust"] == "untrusted"
