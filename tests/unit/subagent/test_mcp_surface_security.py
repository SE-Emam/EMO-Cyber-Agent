"""MCP security black-box tests — POST-T018 (Agent 5D).

Black-box only: exercises the REAL MCP server via
``create_server`` + ``handle_message`` plus subagent contract models
(``tool_filter.filter_tools``, ``discovery``). No source edits, no mocks
of the server internals.
"""

from __future__ import annotations

import json
from typing import Any

from emo_cyber_agent.mcp import protocol as proto
from emo_cyber_agent.mcp.server import create_server
from emo_cyber_agent.mcp.tools import TOOL_NAMES
from emo_cyber_agent.subagent import discovery as _discovery
from emo_cyber_agent.subagent.tool_filter import filter_tools

EXPECTED_TOOLS = (
    "cyber_audit",
    "cyber_extensions",
    "cyber_report",
    "cyber_review",
    "cyber_status",
    "cyber_verify",
)


def _send(server: Any, message: Any) -> dict[str, Any]:
    resp = server.handle_message(message)
    assert isinstance(resp, dict), message
    return resp


def _status_call(server: Any, req_id: int = 1, extra_params: Any = None) -> dict[str, Any]:
    params: dict[str, Any] = {"name": "cyber_status", "arguments": {}}
    if extra_params:
        params.update(extra_params)
    return _send(
        server,
        {"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params},
    )


def _result_payload(response: dict[str, Any]) -> Any:
    assert "result" in response, response
    return response["result"]


# -- initialize handshake ----------------------------------------------------


def test_initialize_handshake():
    server = create_server()
    resp = _send(
        server,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26"}},
    )
    assert resp["result"]["protocolVersion"] == "2025-03-26"
    assert resp["result"]["serverInfo"]["name"] == "emo-cyber-agent"
    assert "tools" in resp["result"]["capabilities"]

    # Unknown version falls back to latest, never errors.
    resp2 = _send(
        server,
        {"jsonrpc": "2.0", "id": 2, "method": "initialize",
         "params": {"protocolVersion": "1999-00-00"}},
    )
    assert resp2["result"]["protocolVersion"] == proto.LATEST_PROTOCOL_VERSION

    # ping works; notifications get no response.
    assert _send(server, {"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {}})["result"] == {}
    assert server.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) is None


# -- tools/list shape --------------------------------------------------------


def test_tools_list_shape_six_tools_no_leak():
    server = create_server()
    resp = _send(server, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    tools = _result_payload(resp)["tools"]
    assert sorted(t["name"] for t in tools) == sorted(EXPECTED_TOOLS)
    assert len(tools) == 6
    assert tuple(sorted(TOOL_NAMES)) == tuple(sorted(EXPECTED_TOOLS))
    # Contract mirror agrees on the 6-tool surface.
    assert tuple(sorted(_discovery.list_tools())) == tuple(sorted(EXPECTED_TOOLS))
    blob = json.dumps(tools).lower()
    for leaked in ("semgrep", "trivy", "gitleaks", "osv", "github api", "supabase"):
        assert leaked not in blob
    for tool in tools:
        assert tool["inputSchema"]["type"] == "object"
        assert tool["description"] and len(tool["description"]) <= 2000
    desc_blob = json.dumps([t["description"] for t in tools]).lower()
    for claim in ("write repository", "delete database", "execute arbitrary"):
        assert claim not in desc_blob


# -- malicious tool metadata --------------------------------------------------


def test_malicious_tool_metadata_rejected():
    server = create_server()
    # Unknown *method* is protocol-level METHOD_NOT_FOUND.
    resp = _send(server, {"jsonrpc": "2.0", "id": 1, "method": "tools/delete", "params": {}})
    assert resp["error"]["code"] == proto.METHOD_NOT_FOUND

    # Unknown *tool* inside tools/call is an INVALID (INVALID_PARAMS) reject.
    for bad_name in ("cyber_pwn", "semgrep", "", "../escape"):
        resp = _send(
            server,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": bad_name, "arguments": {}}},
        )
        assert resp["error"]["code"] == proto.INVALID_PARAMS, bad_name
        assert "traceback" not in json.dumps(resp).lower()

    # Malformed params shapes are INVALID, never internal errors.
    malformed = [
        {"name": "cyber_status", "arguments": "just run it"},
        {"name": "cyber_status", "arguments": None},
        {"name": "cyber_audit", "arguments": {}},  # missing required target
        {"name": "cyber_audit", "arguments": {"target": ".", "bogus": 1}},
        {"name": "cyber_audit", "arguments": {"target": ".", "secret": "x"}},
        {"name": "cyber_audit", "arguments": {"target": ".", "shell": True}},
    ]
    for i, params in enumerate(malformed):
        resp = _send(
            server,
            {"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call", "params": params},
        )
        assert resp["error"]["code"] == proto.INVALID_PARAMS, params
    # Non-object params envelope itself.
    resp = _send(server, {"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": "oops"})
    assert resp["error"]["code"] == proto.INVALID_PARAMS


# -- malformed JSON-RPC ---------------------------------------------------------


def test_malformed_jsonrpc_invalid_request():
    server = create_server()
    assert _send(
        server, {"jsonrpc": "1.0", "id": 1, "method": "tools/list", "params": {}}
    )["error"]["code"] == proto.INVALID_REQUEST
    assert _send(server, [{"jsonrpc": "2.0", "id": 1, "method": "ping"}])["error"]["code"] == proto.INVALID_REQUEST
    assert _send(server, "nope")["error"]["code"] == proto.INVALID_REQUEST
    assert _send(server, {"jsonrpc": "2.0", "id": 5, "method": 123})["error"]["code"] == proto.INVALID_REQUEST
    assert _send(server, {"id": 6, "method": "ping"})["error"]["code"] == proto.INVALID_REQUEST


# -- progressToken abuse ----------------------------------------------------------


def test_progress_token_abuse_request_still_succeeds_zero_notifications():
    bad_tokens = [
        "x" * 300,  # oversized (>256)
        "y" * 10000,  # grossly oversized
        True,  # bool forbidden
        False,
        -5,  # negative int
        "",  # blank
        "   ",
        {"evil": 1},  # non-scalar
        ["tok"],
        3.14,
        None,
    ]
    for i, token in enumerate(bad_tokens):
        server = create_server()
        resp = _send(
            server,
            {"jsonrpc": "2.0", "id": i + 1, "method": "tools/call",
             "params": {"name": "cyber_status", "arguments": {}, "_meta": {"progressToken": token}}},
        )
        assert "result" in resp, (token, resp)
        assert server.drain_notifications() == [], token


def test_progress_token_valid_binds_only_allowed_fields():
    server = create_server()
    resp = _status_call(server, extra_params={"_meta": {"progressToken": "tok-ok"}})
    assert "result" in resp
    notes = server.drain_notifications()
    assert len(notes) >= 1
    for note in notes:
        assert note["method"] == "notifications/progress"
        assert "id" not in note
        params = note["params"]
        assert params["progressToken"] == "tok-ok"
        assert set(params) == {"progressToken", "phase", "percent", "message_code"}


# -- session isolation ---------------------------------------------------------------


def test_session_isolation_token_a_never_leaks():
    server = create_server()
    r1 = _send(
        server,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "cyber_status", "arguments": {}, "_meta": {"progressToken": "token-A-xyz"}}},
    )
    assert "result" in r1
    notes_a = server.drain_notifications()
    assert len(notes_a) >= 1
    assert all(n["params"]["progressToken"] == "token-A-xyz" for n in notes_a)

    # Token-less call on the same server: succeeds, zero notifications,
    # and its response carries no trace of token A.
    r2 = _send(
        server,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "cyber_status", "arguments": {}}},
    )
    assert "result" in r2
    assert server.drain_notifications() == []
    assert "token-A-xyz" not in json.dumps(r2)
    assert "token-A-xyz" not in json.dumps(server.drain_notifications())


# -- result firewall spot-check --------------------------------------------------------


def test_result_firewall_spot_check_no_secrets_or_paths():
    server = create_server()
    blobs: list[str] = []
    blobs.append(json.dumps(_send(
        server,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26"}})))
    blobs.append(json.dumps(_send(server, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})))
    blobs.append(json.dumps(_status_call(server, req_id=3)))
    blobs.append(json.dumps(_send(
        server,
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "cyber_extensions", "arguments": {"action": "list"}}})))
    blobs.append(json.dumps(_send(
        server,
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "cyber_pwn", "arguments": {}}})))
    combined = "\n".join(blobs)
    lowered = combined.lower()
    for marker in ("ghp_", "gho_", "sk-live", "sk-ant-",
                   "begin private key", "aws_secret_access_key",
                   "/etc/shadow", "/etc/passwd", "traceback", "stacktrace"):
        assert marker not in lowered, marker
    assert "/Users/" not in combined
    assert "/etc/" not in combined


# -- tool filtering contract on the real 6-tool surface ----------------------------------


def test_tool_filtering_contract_deny_wins_on_real_surface():
    available = list(TOOL_NAMES)
    assert len(available) == 6

    out = filter_tools(available, ["cyber_audit", "cyber_review", "cyber_status"], ["cyber_review"])
    assert out["allowed"] == ("cyber_audit", "cyber_status")
    assert out["denied_with_reasons"]["cyber_review"] == "denied:cyber_review"

    out = filter_tools(available, ["cyber_audit", "cyber_nope"], ["cyber_ghost"])
    assert "cyber_nope" not in out["allowed"]
    assert out["denied_with_reasons"]["cyber_nope"] == "unknown-tool:cyber_nope"
    assert out["denied_with_reasons"]["cyber_ghost"] == "unknown-tool:cyber_ghost"

    out = filter_tools(available, [])
    assert out["allowed"] == ()
    assert set(out["denied_with_reasons"]) == set(available)

    out = filter_tools(available, ["*"])
    assert out["allowed"] == ()
    assert out["denied_with_reasons"]["*"] == "wildcard-forbidden:*"

    first = filter_tools(available, ["cyber_verify", "cyber_audit"], ["cyber_audit"])
    second = filter_tools(available, ["cyber_verify", "cyber_audit"], ["cyber_audit"])
    assert first == second
    assert first["allowed"] == ("cyber_verify",)
    assert list(first["denied_with_reasons"]) == sorted(first["denied_with_reasons"])
