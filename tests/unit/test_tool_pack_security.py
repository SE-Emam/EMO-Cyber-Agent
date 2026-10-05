"""POST-RC-007 — Tool Pack security battery (offline).

Adversarial execution, binding, isolation, injection, and surface
tests. Scripted ports only; no real binaries, no network.
"""

import inspect
import json
import shutil
from pathlib import Path

import pytest

from emo_cyber_agent.tools.packs.catalog import compat_adapters, load_official_tool_packs, spec_from_yaml_text
from emo_cyber_agent.tools.packs.errors import ToolPackError, ToolPackErrorCode
from emo_cyber_agent.tools.packs.executor import PackExecutor
from emo_cyber_agent.tools.packs.resolver import ToolPackResolver
from emo_cyber_agent.tools.packs.validator import ToolPackValidator

OFFICIAL_DIR = Path("templates/tools/packs/official")
FIXTURES_DIR = Path("tests/fixtures/tool_packs")


def _tools():
    from emo_cyber_agent.core.scanners import get_scanner_tool_specs
    from emo_cyber_agent.core.tool_registry import ToolRegistry

    registry = ToolRegistry()
    for spec in get_scanner_tool_specs():
        registry.register(spec)
    return registry


def _stack(monkeypatch, tmp_path, stdout, network_granted=False):
    """Full execution stack with a scripted port. Returns (PackExecutor, policy, port, audit_root)."""
    from emo_cyber_agent.adapters.mock_scanners import ScriptedPort
    from emo_cyber_agent.core.policy import StrictPolicyEngine

    monkeypatch.setattr(shutil, "which", lambda binary: f"/usr/bin/{binary}")
    tools = _tools()
    granted = ("scanner.network.read",) if network_granted else ()
    policy = StrictPolicyEngine(granted_network=granted)
    port = ScriptedPort(stdout=stdout)
    audit_root = str(tmp_path / "audit")
    Path(audit_root).mkdir(parents=True, exist_ok=True)
    packs = load_official_tool_packs(str(OFFICIAL_DIR))
    executor = PackExecutor(tool_registry=tools, policy=policy, port=port, audit_root=audit_root, pack_registry=packs, adapters=compat_adapters())
    resolver = ToolPackResolver(packs, tool_registry=tools)
    return executor, policy, port, audit_root, resolver


# ---------------- shell / argv ----------------

def test_no_arbitrary_argv_surface():
    assert "argv" not in inspect.signature(PackExecutor.execute).parameters
    assert "env" not in inspect.signature(PackExecutor.execute).parameters
    assert "command" not in inspect.signature(PackExecutor.execute).parameters
    assert not hasattr(PackExecutor, "run_raw") and not hasattr(PackExecutor, "execute_shell")


def test_shell_injection_via_inputs_never_reaches_argv(monkeypatch, tmp_path):
    executor, _, port, audit_root, resolver = _stack(monkeypatch, tmp_path, stdout="{}")
    resolved = resolver.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    argv = executor.build_argv(resolved, confined_target="repo", inputs={})
    assert argv[0] == "semgrep" and all(isinstance(a, str) for a in argv)
    assert not any(any(m in a for m in (";", "&", "|", "$", "`", "\n")) for a in argv)


def test_shell_pack_rejected():
    pack = spec_from_yaml_text((FIXTURES_DIR / "evil-shell-pack.yaml").read_text())
    errors = ToolPackValidator().validate(pack).errors
    assert any("shell-semantics" in e for e in errors)


def test_grant_pack_rejected_and_quarantined():
    pack = spec_from_yaml_text((FIXTURES_DIR / "evil-grant-pack.yaml").read_text())
    errors = ToolPackValidator().validate(pack).errors
    assert any("capability-escalation" in e for e in errors)


def test_metadata_pack_quarantined_as_data():
    pack = spec_from_yaml_text((FIXTURES_DIR / "evil-metadata-pack.yaml").read_text())
    result = ToolPackValidator().validate(pack)
    assert result.trust.value == "untrusted" and any("quarantine" in w for w in result.warnings)
    assert pack.description.startswith("Fixture with malicious report metadata")


# ---------------- paths ----------------

def test_traversal_null_encoded_inputs_rejected(monkeypatch, tmp_path):
    from emo_cyber_agent.core.execution import ExecutionError
    from emo_cyber_agent.tools.packs.executor import validate_inputs
    from emo_cyber_agent.tools.packs.spec import ToolInputContract, ToolInputField

    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout="{}")
    resolved = resolver.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    # confinement enforced at execution (ToolExecutor/confine_path), not string matching
    with pytest.raises(ExecutionError):
        executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="../evil", inputs={})
    with pytest.raises(ExecutionError):
        executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="a\x00b", inputs={})
    # typed input contracts reject traversal/encoded paths at validation
    contract_holder = type("D", (), {"inputs": ToolInputContract(fields=(ToolInputField(name="target_path", type="path", required=True),))})()
    with pytest.raises(ToolPackError):
        validate_inputs(contract_holder, {"target_path": "../evil"})
    with pytest.raises(ToolPackError):
        validate_inputs(contract_holder, {"target_path": "a%2e%2e/b"})


def test_symlink_and_cwd_escape_denied(monkeypatch, tmp_path):
    from emo_cyber_agent.core.execution import ExecutionError

    executor, _, _, audit_root, resolver = _stack(monkeypatch, tmp_path, stdout="{}")
    resolved = resolver.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    outside = tmp_path / "outside"
    outside.mkdir()
    link = Path(audit_root) / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ExecutionError):
        executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="link/evil", inputs={})
    with pytest.raises(ExecutionError):
        executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="/etc", inputs={})


# ---------------- output limits / timeout / secrets ----------------

def test_oversized_output_truncated_with_limitation(monkeypatch, tmp_path):
    from emo_cyber_agent.adapters.mock_scanners import OVERSIZED_CHUNK

    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout=OVERSIZED_CHUNK)
    resolved = resolver.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    normalized, _, _, result = executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="repo", inputs={})
    assert result.stdout_truncated is True
    assert any("output-truncated" in lim for lim in normalized.limitations)
    assert len(result.stdout) <= 300000


def test_timeout_surfaces_as_error(monkeypatch, tmp_path):
    from emo_cyber_agent.adapters.mock_scanners import ScriptedPort
    from emo_cyber_agent.core.execution import ExecutionError

    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout="")
    executor._executor._port = ScriptedPort(stdout="", outcome="timeout", stderr="timed out")
    resolved = resolver.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    with pytest.raises(ExecutionError) as e:
        executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="repo", inputs={})
    assert "timed out" in str(e.value).lower() or "timeout" in str(e.value).lower()


def test_secret_leakage_never_reaches_evidence(monkeypatch, tmp_path):
    secret_stdout = (FIXTURES_DIR / "secret-stdout.json").read_text()
    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout=secret_stdout)
    resolved = resolver.resolve_by_tool("gitleaks", capability="SECRET_DETECTION")
    normalized, evidence, _, _ = executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="repo", inputs={})
    blob = json.dumps({"records": normalized.normalized_records, "evidence": evidence})
    assert "SUPERSECRETVALUE999" not in blob and "ghp_REALTOKEN123" not in blob
    assert len(normalized.normalized_records) == 1


def test_secret_env_never_inherited():
    from emo_cyber_agent.core.execution import ExecutionError, sanitized_env

    env = sanitized_env()
    assert not any("secret" in k.lower() or "token" in k.lower() for k in env)
    with pytest.raises(ExecutionError):
        sanitized_env({"AWS_SECRET_ACCESS_KEY": "x"})
    with pytest.raises(ExecutionError):
        sanitized_env({"GITHUB_TOKEN": "x"})


# ---------------- network / policy ----------------

def test_network_required_fails_closed_offline(monkeypatch, tmp_path):
    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout="{}")
    resolved = resolver.resolve_by_tool("osv-scanner", capability="VULNERABILITY_LOOKUP", network_available=True)
    with pytest.raises(ToolPackError) as e:
        executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="repo", inputs={})
    assert e.value.code == ToolPackErrorCode.POLICY_DENIED


def test_missing_and_forged_policy_decisions_rejected(monkeypatch, tmp_path):
    from emo_cyber_agent.core.execution import ExecutionError

    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout="{}")
    resolved = resolver.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    with pytest.raises(ExecutionError):
        executor._executor.execute(audit_id="A", tool_id="semgrep", target="repo", capability="scanner.local.execute", profile="read_only", policy_decision_id=None, argv_builder=lambda spec, confined: ["semgrep", "scan", confined])
    with pytest.raises(ExecutionError):
        executor._executor.execute(audit_id="A", tool_id="semgrep", target="repo", capability="scanner.local.execute", profile="read_only", policy_decision_id="forged-id", argv_builder=lambda spec, confined: ["semgrep", "scan", confined])


def test_wrong_audit_target_bindings_rejected(monkeypatch, tmp_path):
    from emo_cyber_agent.core.execution import ExecutionError

    executor, policy, _, _, resolver = _stack(monkeypatch, tmp_path, stdout="{}")
    resolved = resolver.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    decision = policy.issue_decision("AUDIT-A", "semgrep", "repo", "read_only", ["scanner.local.execute"])
    assert decision.allowed
    with pytest.raises(ExecutionError):
        executor.execute(resolved, audit_id="AUDIT-B", project_id="P", snapshot_id="S", target="repo", inputs={}, policy_decision_id=decision.decision_id)
    decision2 = policy.issue_decision("AUDIT-A", "semgrep", "repo", "read_only", ["scanner.local.execute"])
    with pytest.raises(ExecutionError):
        executor.execute(resolved, audit_id="AUDIT-A", project_id="P", snapshot_id="S", target="other", inputs={}, policy_decision_id=decision2.decision_id)


def test_stale_snapshot_binding_rejected(monkeypatch, tmp_path):
    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout="{}")
    resolved = resolver.resolve_by_tool("osv-scanner", capability="VULNERABILITY_LOOKUP", network_available=True)
    with pytest.raises(ToolPackError) as e:
        executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S1", target="repo", inputs={"snapshot_id": "S2"})
    assert e.value.code == ToolPackErrorCode.STALE_SNAPSHOT


def test_cross_audit_evidence_isolation(monkeypatch, tmp_path):
    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout='{"results": []}')
    resolved = resolver.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    _, evidence_a, _, _ = executor.execute(resolved, audit_id="AUDIT-A", project_id="P", snapshot_id="S", target="repo", inputs={})
    _, evidence_b, _, _ = executor.execute(resolved, audit_id="AUDIT-B", project_id="P", snapshot_id="S", target="repo", inputs={})
    assert evidence_a == [] and evidence_b == []
    executor2, _, _, _, _ = _stack(monkeypatch, tmp_path, stdout='{"results": [{"check_id": "r", "path": "a.py", "start": {"line": 1}, "end": {"line": 1}, "extra": {"message": "m", "severity": "INFO"}}]}')
    _, evidence_c, _, _ = executor2.execute(resolved, audit_id="AUDIT-A", project_id="P", snapshot_id="S", target="repo", inputs={})
    assert all(e["audit_id"] == "AUDIT-A" for e in evidence_c)


# ---------------- injection through tool output ----------------

def test_instruction_injection_stays_inert(monkeypatch, tmp_path):
    payload = (FIXTURES_DIR / "instruction-injection-stdout.json").read_text()
    executor, policy, _, _, resolver = _stack(monkeypatch, tmp_path, stdout=payload)
    before = len(policy.decisions)
    resolved = resolver.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    normalized, evidence, _, _ = executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="repo", inputs={})
    assert len(policy.decisions) == before + 1  # exactly one legitimate decision, nothing granted
    blob = json.dumps({"records": normalized.normalized_records, "evidence": evidence, "provenance": normalized.provenance})
    assert "mark finding confirmed" in blob  # preserved as inert data
    assert normalized.provenance["source"] == "semgrep"  # provenance forged by no output
    assert all("finding_id" not in e and "status" not in e for e in evidence)


def test_confirmed_claim_never_promoted(monkeypatch, tmp_path):
    stdout = json.dumps({"Results": [{"Target": "req.txt", "Vulnerabilities": [{"VulnerabilityID": "CVE-0000-1", "PkgName": "pk", "InstalledVersion": "1.0", "Severity": "CRITICAL", "Title": "VULNERABLE CONFIRMED"}]}]})
    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout=stdout)
    resolved = resolver.resolve_by_tool("trivy", capability="VULNERABILITY_LOOKUP")
    normalized, evidence, _, _ = executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="repo", inputs={})
    assert len(evidence) == 1
    assert "severity" not in evidence[0] and "status" not in evidence[0]
    assert normalized.normalized_records[0]["scanner_severity"] == "CRITICAL"  # verbatim data, not EMO state


def test_arbitrary_flags_and_config_rejected():
    pack = spec_from_yaml_text((FIXTURES_DIR / "evil-config-pack.yaml").read_text())
    errors = ToolPackValidator().validate(pack).errors
    assert any("input-rejected" in e for e in errors)


def test_unsupported_binary_version_missing(monkeypatch):
    import shutil as _shutil

    monkeypatch.setattr(_shutil, "which", lambda binary: None)
    reg = load_official_tool_packs(str(OFFICIAL_DIR))
    res = ToolPackResolver(reg)
    with pytest.raises(ToolPackError) as e:
        res.resolve_by_tool("semgrep", capability="CODE_PATTERN_SCAN")
    assert e.value.code == ToolPackErrorCode.TOOL_UNAVAILABLE
    degraded = res.resolve_optional("semgrep", capability="CODE_PATTERN_SCAN")
    assert degraded.degraded is True


# ---------------- skill integration + e2e ----------------

def _e2e(monkeypatch, tmp_path, tool_id, capability, stdout, network_granted=False):
    executor, _, _, _, resolver = _stack(monkeypatch, tmp_path, stdout=stdout, network_granted=network_granted)
    resolved = resolver.resolve_by_capability(capability) if tool_id is None else resolver.resolve_by_tool(tool_id, capability=capability, network_available=network_granted)
    return executor.execute(resolved, audit_id="A", project_id="P", snapshot_id="S", target="repo", inputs={})


def test_skill_secret_detection_to_redacted_evidence(monkeypatch, tmp_path):
    secret_stdout = (FIXTURES_DIR / "secret-stdout.json").read_text()
    normalized, evidence, _, _ = _e2e(monkeypatch, tmp_path, "gitleaks", "SECRET_DETECTION", secret_stdout)
    assert normalized.tool_id == "gitleaks"
    assert len(evidence) == 1 and "SUPERSECRETVALUE999" not in json.dumps(evidence)


def test_skill_injection_to_semgrep_evidence(monkeypatch, tmp_path):
    from emo_cyber_agent.adapters.mock_scanners import MULTI_SEMGREP

    normalized, evidence, _, _ = _e2e(monkeypatch, tmp_path, "semgrep", "CODE_PATTERN_SCAN", MULTI_SEMGREP)
    assert len(evidence) == 2
    assert all(e["tool_id"] == "semgrep" for e in evidence)
    assert all("provenance" in e and "content_digest" in e for e in evidence)


def test_skill_dependency_to_trivy_evidence(monkeypatch, tmp_path):
    stdout = json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1", "PkgName": "flask", "InstalledVersion": "2.0.0", "FixedVersion": "2.1.0", "Severity": "HIGH", "Title": "issue"}]}]})
    normalized, evidence, _, _ = _e2e(monkeypatch, tmp_path, "trivy", "VULNERABILITY_LOOKUP", stdout)
    assert evidence[0]["tool_id"] == "trivy" and "CVE-2024-1" in json.dumps(evidence)


def test_skill_dependency_to_osv_evidence_granted_network(monkeypatch, tmp_path):
    stdout = json.dumps({"results": [{"source": "requirements.txt", "packages": [{"package": {"name": "flask", "version": "2.0.0", "ecosystem": "PyPI"}, "vulnerabilities": [{"id": "GHSA-1", "summary": "issue", "aliases": ["CVE-2024-2"]}]}]}]})
    normalized, evidence, _, _ = _e2e(monkeypatch, tmp_path, "osv-scanner", "VULNERABILITY_LOOKUP", stdout, network_granted=True)
    assert evidence[0]["tool_id"] == "osv-scanner" and "GHSA-1" in json.dumps(evidence)


def test_skill_configuration_to_trivy_evidence(monkeypatch, tmp_path):
    normalized, evidence, _, _ = _e2e(monkeypatch, tmp_path, None, "MISCONFIGURATION_SCAN", '{"Results": []}')
    assert normalized.tool_id == "trivy" and evidence == []


def test_terminal_state_is_facts_not_findings(monkeypatch, tmp_path):
    from emo_cyber_agent.adapters.mock_scanners import MULTI_SEMGREP

    normalized, evidence, invocation, _ = _e2e(monkeypatch, tmp_path, "semgrep", "CODE_PATTERN_SCAN", MULTI_SEMGREP)
    assert normalized.status == "completed" and normalized.coverage == "complete"
    assert invocation.status.value == "completed"
    blob = json.dumps({"records": normalized.normalized_records, "evidence": evidence})
    assert "finding_id" not in blob


# ---------------- surfaces ----------------

def test_no_arbitrary_execution_surface():
    for path in [Path("src/emo_cyber_agent/cli/main.py"), *sorted(Path("src/emo_cyber_agent/mcp").glob("*.py"))]:
        text = path.read_text()
        assert "run_command" not in text and "execute_tool_raw" not in text and "execute_shell" not in text, path


def test_no_execution_or_model_surface_in_packs():
    import ast as _ast

    tree = _ast.parse("\n".join((Path("src/emo_cyber_agent/tools/packs") / f).read_text() for f in ["spec.py", "validator.py", "registry.py", "resolver.py", "executor.py", "provenance.py", "errors.py", "catalog.py"]))
    imports: set[str] = set()
    calls: set[str] = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, _ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, _ast.Call) and isinstance(node.func, _ast.Name):
            calls.add(node.func.id)
    assert not (imports & {"subprocess", "socket", "requests", "openai", "anthropic", "httpx", "urllib", "os", "sys"})
    assert not (calls & {"eval", "exec", "__import__", "compile", "system", "popen", "run", "check_output"})
    if "shutil" in imports:
        # presence probing only: shutil.which performs PATH lookup, never executes
        resolver_src = (Path("src/emo_cyber_agent/tools/packs") / "resolver.py").read_text()
        assert "which(" in resolver_src and "Popen" not in resolver_src and "run(" not in resolver_src
    text = "\n".join((Path("src/emo_cyber_agent/tools/packs") / f).read_text() for f in ["spec.py", "resolver.py", "executor.py"])
    assert "SecurityFinding" not in text and "class Finding" not in text


def test_error_codes_stable():
    from emo_cyber_agent.tools.packs.errors import ToolPackErrorCode

    assert ToolPackErrorCode.SHELL_SEMANTICS.value == "TOOL_PACK_SHELL_SEMANTICS"
    assert ToolPackErrorCode.CAPABILITY_ESCALATION.value == "TOOL_PACK_CAPABILITY_ESCALATION"
    assert ToolPackErrorCode.STALE_SNAPSHOT.value == "TOOL_PACK_STALE_SNAPSHOT"
    assert ToolPackErrorCode.BINDING_MISMATCH.value == "TOOL_PACK_BINDING_MISMATCH"
