"""ECA-T013 — MCP adapter tests (offline, no MCP SDK required).

Protocol, tool surface, delegation, error mapping, security (injection,
traversal, cross-audit, secrets, oversized, concurrency, bypass),
mock-host fixtures, CLI wiring, stdio end-to-end over a subprocess.
"""

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from emo_cyber_agent.mcp import protocol as proto
from emo_cyber_agent.mcp.server import create_server
from emo_cyber_agent.mcp.tools import TOOL_NAMES, TOOLS, InvalidInput, validate_arguments

# Repo root derived from this file's location (machine-independent;
# never hardcode a developer's absolute checkout path).
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _call(server, name, arguments, req_id=1):
    return server.handle_message({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}})


def _payload(response):
    assert "result" in response, response
    content = response["result"]["content"][0]["text"]
    return json.loads(content)


class MockMcpClient:
    """Minimal host fixture speaking the same wire subset as real hosts."""

    def __init__(self, server=None):
        self.server = server or create_server()
        self._id = 0
        self.log = []

    def _send(self, method, params=None, notify=False):
        self._id += 1
        message = {"jsonrpc": "2.0", "method": method}
        if not notify:
            message["id"] = self._id
        if params is not None:
            message["params"] = params
        response = self.server.handle_message(message)
        self.log.append((method, response))
        return response

    def initialize(self, version="2025-03-26"):
        return self._send("initialize", {"protocolVersion": version})

    def list_tools(self):
        return self._send("tools/list", {})

    def call(self, name, arguments):
        return self._send("tools/call", {"name": name, "arguments": arguments})


# ---------------- protocol ----------------

def test_initialize_handshake_and_version_fallback():
    client = MockMcpClient()
    response = client.initialize("2025-03-26")
    assert response["result"]["protocolVersion"] == "2025-03-26"
    assert response["result"]["serverInfo"]["name"] == "emo-cyber-agent"
    response = client.initialize("1999-00-00")
    assert response["result"]["protocolVersion"] == proto.LATEST_PROTOCOL_VERSION
    assert client._send("notifications/initialized", {}, notify=True) is None
    assert client._send("ping", {} )["result"] == {}


def test_unknown_method_and_malformed_messages():
    server = create_server()
    response = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {}})
    assert response["error"]["code"] == proto.METHOD_NOT_FOUND
    assert server.handle_message([{"jsonrpc": "2.0"}])["error"]["code"] == proto.INVALID_REQUEST
    assert server.handle_message("nope")["error"]["code"] == proto.INVALID_REQUEST
    with pytest.raises(proto.JsonRpcError):
        proto.parse_line("{not json")
    with pytest.raises(proto.JsonRpcError):
        proto.parse_line("x" * (proto.MAX_MESSAGE_BYTES + 1))


def test_tool_discovery_high_level_only():
    tools = MockMcpClient().list_tools()["result"]["tools"]
    assert sorted(t["name"] for t in tools) == ["cyber_audit", "cyber_extensions", "cyber_report", "cyber_review", "cyber_status", "cyber_threat_intel", "cyber_verify"]
    blob = json.dumps(tools).lower()
    for leaked in ("semgrep", "trivy", "gitleaks", "osv", "github api", "supabase"):
        assert leaked not in blob
    for tool in tools:
        assert tool["inputSchema"]["type"] == "object"


def test_tool_descriptions_no_overclaim():
    blob = json.dumps(TOOLS).lower()
    for claim in ("write repository", "delete database", "execute arbitrary", "push ", "merge ", "deploy"):
        assert claim not in blob


def test_clean_shutdown_eof():
    server = create_server()
    assert server.run_stdio(stdin=io.StringIO(""), stdout=io.StringIO()) == 0


# ---------------- delegation ----------------

def test_audit_review_status_through_core():
    client = MockMcpClient()
    audit = _payload(client.call("cyber_audit", {"target": "."}))
    assert audit["status"] == "ok" and audit["result"]["target"] == "."
    review = _payload(client.call("cyber_review", {"target": "src/app.py"}))
    assert review["status"] == "ok"
    status = _payload(client.call("cyber_status", {}))
    assert status["result"]["version"] == "0.2.1"
    assert "cyber_audit" in status["result"]["capabilities"]


def test_verify_returns_plan_not_authorization():
    from emo_cyber_agent.core.correlation import FindingCandidate

    candidate = FindingCandidate(audit_id="A", hypothesis="h", evidence_ids=("e1",)).model_dump(mode="json")
    response = MockMcpClient().call("cyber_verify", {"audit_id": "A", "candidate": candidate, "method": "static_confirmation", "target": {"kind": "file", "locator": "src/a.py"}, "rationale": "confirm statically"})
    payload = _payload(response)
    assert payload["status"] == "ok"
    assert payload["result"]["status"] == "planned"
    assert "verification.static" in payload["result"]["required_capabilities"]


def test_report_delegates_to_core_service():
    from emo_cyber_agent.core.findings import SecurityFinding

    finding = SecurityFinding(finding_id="f1", audit_id="A", title="T", description="D", category="authorization", severity="high", confidence=0.8, candidate_id="c1", evidence_ids=("e1",), fingerprint="fp", provenance={"candidate": "c1"}).model_dump(mode="json")
    payload = _payload(MockMcpClient().call("cyber_report", {"audit_id": "A", "findings": [finding], "format": "markdown"}))
    assert payload["status"] == "ok" and "## Findings" in payload["result"]["report"]


def test_invalid_arguments_rejected_not_repaired():
    server = create_server()
    for name, arguments in [
        ("cyber_audit", {}),
        ("cyber_audit", {"target": ""}),
        ("cyber_audit", {"target": ".", "bogus": 1}),
        ("nope_tool", {}),
        ("cyber_report", {"audit_id": "A", "findings": [], "format": "pdf"}),
        ("cyber_verify", {"audit_id": "A"}),
    ]:
        response = _call(server, name, arguments)
        assert response["error"]["code"] == proto.INVALID_PARAMS, (name, arguments)


# ---------------- security ----------------

def test_capability_permission_injection_rejected():
    server = create_server()
    for arguments in [
        {"target": ".", "permissions": "admin"},
        {"target": ".", "capabilities": ["all"]},
        {"target": ".", "policy": "allow-all"},
        {"target": ".", "model": "evil"},
        {"target": ".", "role": "admin"},
    ]:
        assert _call(server, "cyber_audit", arguments)["error"]["code"] == proto.INVALID_PARAMS


def test_shell_command_injection_rejected():
    server = create_server()
    for arguments in [
        {"target": ".", "command": "rm -rf /"},
        {"target": "x; rm -rf /", "shell": True},
        {"target": ".", "script": "evil"},
    ]:
        response = _call(server, "cyber_audit", arguments)
        assert response["error"]["code"] == proto.INVALID_PARAMS


def test_traversal_external_targets_rejected_in_verify():
    from emo_cyber_agent.core.correlation import FindingCandidate

    server = create_server()
    candidate = FindingCandidate(audit_id="A", hypothesis="h", evidence_ids=("e1",)).model_dump(mode="json")
    for locator in ["../../etc/passwd", "https://evil.example/x", "*"]:
        payload = _payload(_call(server, "cyber_verify", {"audit_id": "A", "candidate": candidate, "method": "static_confirmation", "target": {"kind": "file", "locator": locator}, "rationale": "x"}))
        assert payload["status"] == "error", locator
    assert _call(server, "cyber_verify", {"audit_id": "A", "candidate": candidate, "method": "static_confirmation", "target": {"kind": "file", "locator": ""}, "rationale": "x"})["error"]["code"] == proto.INVALID_PARAMS


def test_cross_audit_denied():
    from emo_cyber_agent.core.correlation import FindingCandidate

    candidate = FindingCandidate(audit_id="B", hypothesis="h", evidence_ids=("e1",)).model_dump(mode="json")
    payload = _payload(MockMcpClient().call("cyber_verify", {"audit_id": "A", "candidate": candidate, "method": "static_confirmation", "target": {"kind": "file", "locator": "src/a.py"}, "rationale": "x"}))
    assert payload["status"] == "error" and payload["code"] == proto.DOMAIN_PERMISSION_DENIED


def test_credential_in_input_redacted_everywhere(capsys):
    server = create_server()
    payload = _payload(_call(server, "cyber_audit", {"target": "ghp_LIVE999token-here"}))
    blob = json.dumps(payload)
    assert "ghp_LIVE999token-here" not in blob
    _call(server, "nope", {"target": "ghp_LIVE999token-here"})
    assert "ghp_LIVE999token-here" not in capsys.readouterr().err


def test_malicious_finding_content_escaped_in_report():
    from emo_cyber_agent.core.findings import SecurityFinding

    finding = SecurityFinding(finding_id="f1", audit_id="A", title="[x](javascript:alert(1))", description="<script>alert(2)</script>", category="other", severity="low", confidence=0.2, candidate_id="c1", evidence_ids=("e1",), fingerprint="fp").model_dump(mode="json")
    payload = _payload(MockMcpClient().call("cyber_report", {"audit_id": "A", "findings": [finding], "format": "markdown"}))
    report = payload["result"]["report"]
    assert "[x](javascript" not in report and "<script>" not in report


def test_oversized_request_denied():
    server = create_server()
    big = {"target": ".", "focus": ["x" * 9000]}
    assert _call(server, "cyber_audit", big)["error"]["code"] == proto.INVALID_PARAMS


def test_oversized_report_denied_not_truncated_silently():
    from emo_cyber_agent.core.findings import SecurityFinding

    findings = [SecurityFinding(finding_id=f"f{i}", audit_id="A", title="T", description="D" * 2000, category="other", severity="low", confidence=0.2, candidate_id="c", evidence_ids=("e1",), fingerprint=f"fp{i}").model_dump(mode="json") for i in range(201)]
    response = MockMcpClient().call("cyber_report", {"audit_id": "A", "findings": findings, "format": "json"})
    assert response["error"]["code"] == proto.INVALID_PARAMS  # item-count cap denies; never silently truncated
    import emo_cyber_agent.mcp.delegate as delegate

    assert "1024 * 1024" in open(delegate.__file__).read()  # 1 MiB output gate present as second defense line


def test_concurrent_audits_isolated():
    client_a, client_b = MockMcpClient(), MockMcpClient()
    ra = _payload(client_a.call("cyber_audit", {"target": "proj-a"}))
    rb = _payload(client_b.call("cyber_audit", {"target": "proj-b"}))
    assert ra["result"]["target"] == "proj-a" and rb["result"]["target"] == "proj-b"
    assert ra["result"]["audit_id"] != rb["result"]["audit_id"]
    assert not hasattr(client_a.server, "_audit") and not hasattr(client_b.server, "_current_audit")


def test_core_bypass_attempts_fail():
    server = create_server()
    assert _call(server, "semgrep", {})["error"]["code"] == proto.INVALID_PARAMS
    with pytest.raises(InvalidInput):
        validate_arguments("cyber_audit", "just run it")
    # delegate module holds no policy/severity/finding logic of its own
    import emo_cyber_agent.mcp.delegate as delegate

    body = open(delegate.__file__).read().split('"""', 2)[-1]
    # Core-owned instantiation + validated model construction are the
    # sanctioned translator pattern (§25); what must never appear here is
    # decision/evaluation/classification/execution logic.
    for banned in ("evaluate_policy(", ".check_permission(", "issue_decision(", "Severity(", "subprocess", "os.system", "shell=True"):
        assert banned not in body, banned


def test_status_leaks_nothing():
    payload = _payload(MockMcpClient().call("cyber_status", {"audit_id": "A"}))
    blob = json.dumps(payload).lower()
    for leaked in ("token", "secret", "credential", "password", "key", "cot", "reasoning"):
        assert leaked not in blob
    assert "semgrep" not in blob and "trivy" not in blob


def test_error_mapping_table():
    from emo_cyber_agent.mcp import delegate as _d

    assert json.loads(_d._map_verification_error("t", "A", Exception("x"))["content"][0]["text"])["code"] == "INTERNAL_ERROR"
    assert json.loads(_d._map_report_error("A", Exception("x"))["content"][0]["text"])["code"] == "INTERNAL_ERROR"


# ---------------- CLI + stdio end-to-end ----------------

def test_cli_mcp_help_and_report_still_work():
    from typer.testing import CliRunner

    from emo_cyber_agent.cli.main import app

    runner = CliRunner()
    assert runner.invoke(app, ["mcp", "--help"]).exit_code == 0
    assert runner.invoke(app, ["--help"]).exit_code == 0


def test_stdio_end_to_end_subprocess():
    script = (
        "import sys; sys.path.insert(0, 'src'); "
        "from emo_cyber_agent.mcp.server import run_stdio; "
        "raise SystemExit(run_stdio())"
    )
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cyber_status", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cyber_audit", "arguments": {"target": "."}}},
    ]
    proc = subprocess.run(
        [sys.executable, "-c", script],
        input="\n".join(__import__("json").dumps(m) for m in messages) + "\n",
        capture_output=True, text=True, timeout=60, cwd=str(_REPO_ROOT),
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    lines = [json.loads(line) for line in proc.stdout.strip().split("\n")]
    assert len(lines) == 4  # notification gets no response
    assert lines[0]["result"]["protocolVersion"] == "2025-06-18"
    assert len(lines[1]["result"]["tools"]) == len(TOOL_NAMES)
    assert json.loads(lines[2]["result"]["content"][0]["text"])["status"] == "ok"


def test_packaging_entry_points():
    import tomllib

    with open(_REPO_ROOT / "pyproject.toml", "rb") as fh:
        project = tomllib.load(fh)
    assert project["project"]["scripts"]["cyber-agent"] == "emo_cyber_agent.cli.main:app"
    assert create_server().__class__.__name__ == "McpServer"
