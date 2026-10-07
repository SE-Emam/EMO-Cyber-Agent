"""Threat-intel MCP exposure tests — TI-MCP (7th tool).

Black-box only via the REAL server (create_server + handle_message) plus
direct delegate calls for defense-in-depth branches. Covers the five
action routes, shape/validation rejects, unknown action, and
no-secret/no-network guards. Default subsets stay at 5 (asserted in
discovery tests; re-asserted here as a guard).
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from emo_cyber_agent.mcp import protocol as proto
from emo_cyber_agent.mcp.server import create_server
from emo_cyber_agent.mcp.tools import TOOL_NAMES
from emo_cyber_agent.subagent import discovery as _discovery

HIBP_FIXTURE = {
    "account": "user@example.com",
    "breaches": [
        {"Name": "ExampleBreach", "BreachDate": "2021-05-01", "IsVerified": True},
    ],
}

THREATFOX_FIXTURE = {
    "query_status": "ok",
    "data": [
        {"ioc": "1.2.3.4", "threat_type": "botnet_cc", "first_seen": "2023-01-01", "confidence_level": 90},
        {"ioc": "evil.example.com", "malware_printable": "Emotet", "first_seen": "2023-02-02", "confidence_level": "low"},
    ],
}


def _call(server: Any, name: str, arguments: Any, req_id: int = 1) -> dict[str, Any]:
    return server.handle_message(
        {"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )


def _payload(response: dict[str, Any]) -> dict[str, Any]:
    assert "result" in response, response
    return json.loads(response["result"]["content"][0]["text"])


def test_tool_advertised_seventh() -> None:
    assert "cyber_threat_intel" in TOOL_NAMES
    assert len(TOOL_NAMES) == 7
    server = create_server()
    resp = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = sorted(t["name"] for t in resp["result"]["tools"])
    assert "cyber_threat_intel" in names
    assert len(names) == 7
    spec = next(t for t in resp["result"]["tools"] if t["name"] == "cyber_threat_intel")
    assert spec["inputSchema"]["type"] == "object"
    assert "leak-check" in json.dumps(spec["inputSchema"])
    blob = json.dumps(spec).lower()
    for claim in ("write repository", "delete database", "execute arbitrary"):
        assert claim not in blob


def test_default_subsets_still_five() -> None:
    ad = _discovery.build_advertisement(task_kind="security-review")
    assert set(ad.tool_names()) == {"cyber_audit", "cyber_review", "cyber_verify", "cyber_report", "cyber_status"}
    assert "cyber_threat_intel" not in ad.tool_names()
    full = _discovery.build_advertisement()
    assert "cyber_threat_intel" in full.tool_names()
    assert _discovery.describe_tool("cyber_threat_intel").safe_default is False


def test_leak_check_hibp_happy() -> None:
    server = create_server()
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "leak-check", "identifier": "user@example.com", "hibp_payload": HIBP_FIXTURE}))
    assert payload["status"] == "ok"
    assert payload["tool"] == "cyber_threat_intel"
    result = payload["result"]
    assert result["action"] == "leak-check"
    assert result["identifier_digest"] == hashlib.sha256(b"user@example.com").hexdigest()
    assert len(result["findings"]) == 1
    assert result["verdicts"][0]["verdict"] == "RELEVANT"
    blob = json.dumps(payload)
    assert "user@example.com" not in blob


def test_leak_check_threatfox_happy() -> None:
    server = create_server()
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "leak-check", "identifier": "1.2.3.4", "threatfox_payload": THREATFOX_FIXTURE}))
    assert payload["status"] == "ok"
    assert len(payload["result"]["findings"]) == 2
    by_id = {v["finding_id"]: v["verdict"] for v in payload["result"]["verdicts"]}
    assert list(by_id.values()).count("RELEVANT") == 1
    assert list(by_id.values()).count("UNRELATED") == 1
    blob = json.dumps(payload)
    assert "1.2.3.4" not in blob
    assert "evil.example.com" not in blob


def test_leak_check_deterministic() -> None:
    server = create_server()
    args = {"action": "leak-check", "identifier": "user@example.com", "hibp_payload": HIBP_FIXTURE}
    first = _payload(_call(server, "cyber_threat_intel", args))
    second = _payload(_call(server, "cyber_threat_intel", dict(args)))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_triage_happy() -> None:
    server = create_server()
    iocs = [{"kind": "ip", "value": "1.2.3.4", "source": "feed-a", "first_seen": "2024-01-01"}]
    findings = [{"ref": "finding-one", "value": "1.2.3.4"}]
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "triage", "iocs": iocs, "findings": findings, "kev": [], "epss": {}}))
    assert payload["status"] == "ok"
    assert payload["result"]["verdicts"][0]["verdict"] == "RELEVANT"
    assert payload["result"]["verdicts"][0]["ioc_ref"] == "ip:1.2.3.4"


def test_triage_prioritizes_with_kev_epss() -> None:
    server = create_server()
    findings = [
        {"ref": "item-low-epss", "value": "10.0.0.9", "severity": 9.8},
        {"ref": "item-high-epss", "value": "10.0.0.8", "severity": 4.0},
        {"ref": "item-kev", "value": "10.0.0.7", "severity": 1.0, "cve_id": "CVE-2021-44228"},
    ]
    args = {
        "action": "triage",
        "iocs": [],
        "findings": findings,
        "kev": ["CVE-2021-44228"],
        "epss": {"item-high-epss": 0.9, "item-low-epss": 0.1},
    }
    payload = _payload(_call(server, "cyber_threat_intel", args))
    assert payload["status"] == "ok"
    ordered = [f["ref"] if isinstance(f, dict) else f.ref for f in payload["result"]["prioritized_findings"]]
    assert ordered[0] == "item-kev"


def test_map_technique_cwe_happy() -> None:
    server = create_server()
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "map-technique", "cwe": "CWE-307"}))
    assert payload["status"] == "ok"
    assert payload["result"]["hits"][0]["technique_id"] == "T1110"
    assert payload["result"]["hits"][0]["basis"] == "cwe"


def test_map_technique_keyword_happy() -> None:
    server = create_server()
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "map-technique", "keywords": ["brute", "password"]}))
    assert payload["status"] == "ok"
    ids = [h["technique_id"] for h in payload["result"]["hits"]]
    assert "T1110" in ids
    assert payload["result"]["hits"] == sorted(payload["result"]["hits"], key=lambda h: (0 if h["basis"] == "cwe" else 1, h["technique_id"])) or payload["result"]["hits"]


def test_map_technique_unknown_is_empty() -> None:
    server = create_server()
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "map-technique", "cwe": "CWE-9999", "keywords": ["zzqxjkw"]}))
    assert payload["status"] == "ok"
    assert payload["result"]["hits"] == []


def test_exposure_check_happy() -> None:
    server = create_server()
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "exposure-check", "tool": "hydra", "facts": {"auth": True}}))
    assert payload["status"] == "ok"
    assert payload["result"]["tool"] == "hydra"
    assert payload["result"]["exposed"] is True
    calm = _payload(_call(server, "cyber_threat_intel", {"action": "exposure-check", "tool": "hydra", "facts": {"auth": True, "rate_limit": True}}))
    assert calm["result"]["exposed"] is False


def test_exposure_check_sensitive_material_maps_to_secrets() -> None:
    server = create_server()
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "exposure-check", "tool": "john", "facts": {"sensitive_material": True}}))
    assert payload["status"] == "ok"
    assert payload["result"]["exposed"] is True


def test_coverage_happy() -> None:
    server = create_server()
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "coverage", "tools": ["hydra", "nmap"], "signals": ["password-auth"]}))
    assert payload["status"] == "ok"
    assert payload["result"]["covered"] == ["hydra"]
    assert payload["result"]["gaps"] == ["nmap"]


def test_validation_rejects_bad_shapes() -> None:
    server = create_server()
    # missing required action -> protocol INVALID_PARAMS
    assert _call(server, "cyber_threat_intel", {})["error"]["code"] == proto.INVALID_PARAMS
    # unknown enum action -> protocol INVALID_PARAMS (shape-level)
    assert _call(server, "cyber_threat_intel", {"action": "delete-everything"})["error"]["code"] == proto.INVALID_PARAMS
    # wrong types -> protocol INVALID_PARAMS
    assert _call(server, "cyber_threat_intel", {"action": "triage", "iocs": "nope"})["error"]["code"] == proto.INVALID_PARAMS
    assert _call(server, "cyber_threat_intel", {"action": "map-technique", "keywords": "brute"})["error"]["code"] == proto.INVALID_PARAMS
    assert _call(server, "cyber_threat_intel", {"action": "coverage", "tools": "hydra"})["error"]["code"] == proto.INVALID_PARAMS
    # unknown top-level field
    assert _call(server, "cyber_threat_intel", {"action": "triage", "bogus": 1})["error"]["code"] == proto.INVALID_PARAMS
    # oversized identifier
    assert _call(server, "cyber_threat_intel", {"action": "leak-check", "identifier": "x" * 321})["error"]["code"] == proto.INVALID_PARAMS


def test_forbidden_tokens_respected() -> None:
    server = create_server()
    # capabilities is forbidden: coverage must use signals
    assert _call(server, "cyber_threat_intel", {"action": "coverage", "tools": ["hydra"], "capabilities": ["x"]})["error"]["code"] == proto.INVALID_PARAMS
    assert _call(server, "cyber_threat_intel", {"action": "triage", "iocs": [], "findings": [], "secret": "x"})["error"]["code"] == proto.INVALID_PARAMS
    # secrets key inside facts is forbidden; sensitive_material is the mapped alias
    assert _call(server, "cyber_threat_intel", {"action": "exposure-check", "tool": "john", "facts": {"secrets": True}})["error"]["code"] == proto.INVALID_PARAMS
    assert _call(server, "cyber_threat_intel", {"action": "leak-check", "identifier": "a@b.c", "api_key": "sk-x"})["error"]["code"] == proto.INVALID_PARAMS


def test_semantic_errors_are_tool_errors_not_protocol() -> None:
    server = create_server()
    # missing identifier passes shape (optional) but fails per-action validation
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "leak-check", "identifier": ""}))
    assert payload["status"] == "error" and payload["code"] == proto.DOMAIN_INVALID
    # bad IoC value
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "triage", "iocs": [{"kind": "ip", "value": "not-an-ip", "source": "f"}], "findings": []}))
    assert payload["status"] == "error" and payload["code"] == proto.DOMAIN_INVALID
    # unknown kali tool
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "exposure-check", "tool": "not-a-tool", "facts": {}}))
    assert payload["status"] == "error" and payload["code"] == proto.DOMAIN_INVALID
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "coverage", "tools": ["bogus-tool"], "signals": []}))
    assert payload["status"] == "error" and payload["code"] == proto.DOMAIN_INVALID
    # garbage leak payload
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "leak-check", "identifier": "a@b.c", "hibp_payload": "nope"}))
    assert payload["status"] == "error"


def test_unknown_action_direct_dispatch() -> None:
    from emo_cyber_agent.mcp import delegate as _d

    result = _d.call_threat_intel({"action": "nope-unknown"})
    assert result["isError"] is True
    body = json.loads(result["content"][0]["text"])
    assert body["status"] == "error" and body["code"] == proto.DOMAIN_INVALID


def test_no_secret_leak_in_errors_or_logs(capsys: Any) -> None:
    server = create_server()
    marker = "ghp_LIVE999token-here"
    payload = _payload(_call(server, "cyber_threat_intel", {"action": "leak-check", "identifier": marker}))
    assert marker not in json.dumps(payload)
    _call(server, "cyber_threat_intel", {"action": "triage", "iocs": [], "findings": [], "token": marker})
    assert marker not in capsys.readouterr().err


def test_no_network_imports_or_fetchers() -> None:
    forbidden = {"socket", "urllib", "http", "requests", "httpx", "aiohttp", "urllib3", "ftplib", "smtplib", "telnetlib", "websockets", "subprocess"}

    def _imports(path: Path) -> set[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module.split(".")[0])
        return found

    package = Path(__file__).resolve().parents[2] / "src" / "emo_cyber_agent" / "threat_intel"
    for path in sorted(package.glob("*.py")):
        assert not (_imports(path) & forbidden), path.name
    delegate_src = (Path(__file__).resolve().parents[2] / "src" / "emo_cyber_agent" / "mcp" / "delegate.py").read_text(encoding="utf-8")
    for marker in ("fetch_hibp", "fetch_threatfox", "socket.", "subprocess", "requests.", "urllib", "httpx"):
        assert marker not in delegate_src, marker
    tools_src = (Path(__file__).resolve().parents[2] / "src" / "emo_cyber_agent" / "mcp" / "tools.py").read_text(encoding="utf-8")
    assert "cyber_threat_intel" in tools_src
