"""POST-T020 — Streamable HTTP transport tests (stdlib only: urllib/http.client/socket).

Live-socket coverage: init/negotiate/call, session bind + mismatch,
Host/Origin accept+reject, auth present/absent/wrong, oversize reject,
SSE progress shape + inline progress, routing, fail-closed remote bind,
and stdio behavior unchanged (import-only).
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request

import pytest

from emo_cyber_agent.mcp import protocol as proto
from emo_cyber_agent.mcp.http_server import HttpMcpServer, run
from emo_cyber_agent.mcp.server import McpServer
from emo_cyber_agent.subagent.session import SubagentSession

_TOKEN = "tok-http-001"


def _session(**over) -> SubagentSession:
    base = {
        "session_id": "sess-http-001",
        "host_id": "host-local-01",
        "audit_id": "audit-a",
        "project_id": "proj-p",
        "snapshot_id": "snap-s",
        "created": 0,
        "expires": 9999999999,
    }
    base.update(over)
    return SubagentSession(**base)


@pytest.fixture()
def srv():
    server = run("127.0.0.1", 0)
    try:
        yield server
    finally:
        server.stop()


def _post(url, payload, headers=None, raw: bytes | None = None):
    body = raw if raw is not None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read(), dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict((e.headers or {}).items())


def _rpc(method, params=None, req_id=1):
    msg: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


# ---------------- lifecycle over real HTTP ----------------

def test_initialize_negotiate_over_http(srv):
    status, body, _ = _post(srv.url, _rpc("initialize", {"protocolVersion": "2025-03-26"}))
    assert status == 200
    data = json.loads(body)
    assert data["result"]["protocolVersion"] == "2025-03-26"
    assert data["result"]["serverInfo"]["name"] == "emo-cyber-agent"


def test_initialize_unknown_version_falls_back(srv):
    status, body, _ = _post(srv.url, _rpc("initialize", {"protocolVersion": "1999-00-00"}))
    assert status == 200
    assert json.loads(body)["result"]["protocolVersion"] == proto.LATEST_PROTOCOL_VERSION


def test_ping_and_tools_list_over_http(srv):
    status, body, _ = _post(srv.url, _rpc("ping", {}))
    assert status == 200 and json.loads(body)["result"] == {}
    status, body, _ = _post(srv.url, _rpc("tools/list", {}))
    names = {t["name"] for t in json.loads(body)["result"]["tools"]}
    assert "cyber_status" in names and "cyber_audit" in names


def test_tools_call_over_http(srv):
    status, body, _ = _post(
        srv.url, _rpc("tools/call", {"name": "cyber_status", "arguments": {}})
    )
    assert status == 200
    payload = json.loads(json.loads(body)["result"]["content"][0]["text"])
    assert payload["status"] == "ok"


def test_unknown_method_is_jsonrpc_error_not_transport_error(srv):
    status, body, _ = _post(srv.url, _rpc("resources/list", {}))
    assert status == 200
    assert json.loads(body)["error"]["code"] == proto.METHOD_NOT_FOUND


def test_get_mcp_405_and_unknown_path_404(srv):
    base = srv.url.rsplit("/mcp", 1)[0]
    for url, want in ((srv.url, 405), (base + "/nope", 404)):
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
        assert status == want, url


# ---------------- session bind + mismatch ----------------

def _sess_headers(session, **triple_over):
    triple = {
        "X-Eca-Audit-Id": session.audit_id,
        "X-Eca-Project-Id": session.project_id,
        "X-Eca-Snapshot-Id": session.snapshot_id,
    }
    triple.update(triple_over)
    return {"Mcp-Session-Id": session.session_id, **triple}


def test_session_bind_ok_and_echo(srv):
    session = _session()
    srv.register_session(session, now=int(time.time()))
    status, body, headers = _post(srv.url, _rpc("ping", {}), _sess_headers(session))
    assert status == 200
    assert json.loads(body)["result"] == {}
    echoed = {k.lower(): v for k, v in headers.items()}.get("mcp-session-id")
    assert echoed == session.session_id


def test_session_mismatch_440_quarantine_never_dispatched(srv):
    session = _session()
    srv.register_session(session, now=int(time.time()))
    bad = _sess_headers(session, **{"X-Eca-Audit-Id": "audit-INTRUDER"})
    status, body, _ = _post(srv.url, _rpc("ping", {}), bad)
    assert status == 440
    data = json.loads(body)
    assert data.get("quarantine") is True
    # Stored session intact: a correct request still works (never cross-audit).
    status, _, _ = _post(srv.url, _rpc("ping", {}), _sess_headers(session))
    assert status == 200


def test_unknown_session_404(srv):
    status, body, _ = _post(srv.url, _rpc("ping", {}), {"Mcp-Session-Id": "sess-ghost-999"})
    assert status == 404


def test_stale_session_440(srv):
    past = int(time.time()) - 100000
    srv.register_session(_session(), now=past, ttl=60)
    status, body, _ = _post(
        srv.url, _rpc("ping", {}), {"Mcp-Session-Id": "sess-http-001"}
    )
    assert status == 440
    assert json.loads(body).get("quarantine") is True


# ---------------- Host / Origin ----------------

def _raw_request(port, host_value, origin=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = json.dumps(_rpc("ping", {})).encode()
    conn.putrequest("POST", "/mcp", skip_host=True)
    conn.putheader("Host", host_value)
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(body)))
    if origin is not None:
        conn.putheader("Origin", origin)
    conn.endheaders(body)
    resp = conn.getresponse()
    data = (resp.status, resp.read())
    conn.close()
    return data


def test_host_allow_and_reject(srv):
    status, _ = _raw_request(srv.port, "127.0.0.1")
    assert status == 200
    status, _ = _raw_request(srv.port, "localhost")
    assert status == 200
    status, _ = _raw_request(srv.port, "evil.example")
    assert status == 403


def test_origin_absent_ok_foreign_rejected(srv):
    status, _, _ = _post(srv.url, _rpc("ping", {}))  # no Origin: allowed
    assert status == 200
    status, _, _ = _post(srv.url, _rpc("ping", {}), {"Origin": "http://127.0.0.1:9"})
    assert status == 200
    status, _, _ = _post(srv.url, _rpc("ping", {}), {"Origin": "https://evil.example"})
    assert status == 403
    status, _ = _raw_request(srv.port, "127.0.0.1", origin="null")
    assert status == 403


# ---------------- auth ----------------

@pytest.fixture()
def auth_srv(monkeypatch):
    monkeypatch.setenv("EMO_TEST_MCP_BEARER", "s3cret-token")
    server = run("127.0.0.1", 0, bearer_env_var="EMO_TEST_MCP_BEARER")
    try:
        yield server
    finally:
        server.stop()


def test_auth_absent_401_wrong_401_ok_200(auth_srv):
    status, _, _ = _post(auth_srv.url, _rpc("ping", {}))
    assert status == 401
    status, _, _ = _post(auth_srv.url, _rpc("ping", {}), {"Authorization": "Bearer wrong"})
    assert status == 401
    status, body, _ = _post(auth_srv.url, _rpc("ping", {}), {"Authorization": "Bearer s3cret-token"})
    assert status == 200
    assert json.loads(body)["result"] == {}


def test_auth_configured_but_unset_fails_closed(monkeypatch):
    monkeypatch.delenv("EMO_TEST_MCP_MISSING", raising=False)
    server = run("127.0.0.1", 0, bearer_env_var="EMO_TEST_MCP_MISSING")
    try:
        status, _, _ = _post(
            server.url, _rpc("ping", {}), {"Authorization": "Bearer anything"}
        )
        assert status == 401
    finally:
        server.stop()


# ---------------- oversize / malformed ----------------

def test_oversize_rejected_413(srv):
    big = "x" * (proto.MAX_MESSAGE_BYTES + 16)
    status, _, _ = _post(srv.url, _rpc("tools/call", {"name": "cyber_status", "arguments": {"pad": big}}))
    assert status == 413


def test_invalid_json_400(srv):
    status, _, _ = _post(srv.url, None, raw=b"{not json")
    assert status == 400


# ---------------- progress shapes ----------------

def _call_with_token():
    return _rpc(
        "tools/call",
        {"name": "cyber_status", "arguments": {}, "_meta": {"progressToken": _TOKEN}},
    )


def test_progress_sse_stream_shape(srv):
    status, body, headers = _post(srv.url, _call_with_token(), {"Accept": "text/event-stream"})
    assert status == 200
    ctype = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
    assert "text/event-stream" in ctype
    text = body.decode("utf-8")
    blocks = [b for b in text.split("\n\n") if b.strip()]
    kinds = [b.splitlines()[0] for b in blocks]
    assert kinds.count("event: notification") == 4
    assert kinds[-1] == "event: message"
    notes = [json.loads(b.split("data: ", 1)[1]) for b in blocks[:-1]]
    assert [n["method"] for n in notes] == ["notifications/progress"] * 4
    assert [n["params"]["phase"] for n in notes] == ["STARTED", "RUNNING", "FINALIZING", "COMPLETED"]
    assert all(n["params"]["progressToken"] == _TOKEN for n in notes)
    assert "id" not in notes[0]
    final = json.loads(blocks[-1].split("data: ", 1)[1])
    assert "result" in final


def test_progress_inline_before_response_non_sse(srv):
    status, body, _ = _post(srv.url, _call_with_token())
    assert status == 200
    data = json.loads(body)
    assert isinstance(data, list) and len(data) == 5
    assert [n["method"] for n in data[:-1]] == ["notifications/progress"] * 4
    assert "result" in data[-1]


def test_no_token_single_object_response(srv):
    status, body, _ = _post(
        srv.url, _rpc("tools/call", {"name": "cyber_status", "arguments": {}})
    )
    assert status == 200
    assert isinstance(json.loads(body), dict)


# ---------------- fail-closed bind + stdio untouched ----------------

def test_remote_bind_fails_closed():
    with pytest.raises(ValueError):
        run("0.0.0.0", 0)
    with pytest.raises(ValueError):
        HttpMcpServer().start("example.com", 0)


def test_stdio_behavior_unchanged_import_only():
    server = McpServer()
    assert server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "ping"}) == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {},
    }
    assert server.drain_notifications() == []
    assert callable(server.run_stdio)
