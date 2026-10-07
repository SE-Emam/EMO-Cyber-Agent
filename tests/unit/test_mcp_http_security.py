"""POST-T020 G2-C — adversarial HTTP security tests (live sockets, no server mocks).

Live-socket attacks vs HttpMcpServer: Host/Origin, Bearer auth,
payload framing, session binding, slow-request boundedness, concurrency
isolation. Stdlib HTTP only (urllib / http.client / socket).
"""

from __future__ import annotations

import concurrent.futures
import http.client
import json
import socket
import time
import urllib.error
import urllib.request

import pytest

from emo_cyber_agent.mcp import protocol as proto
from emo_cyber_agent.mcp.http_server import run
from emo_cyber_agent.subagent.session import SubagentSession

_JSON = "application/json"


# ---------------------------------------------------------------- helpers


def _session(suffix: str, **over) -> SubagentSession:
    base = {
        "session_id": f"sess-g2c-{suffix}",
        "host_id": f"host-g2c-{suffix}",
        "audit_id": f"audit-{suffix}",
        "project_id": f"proj-{suffix}",
        "snapshot_id": f"snap-{suffix}",
        "created": 0,
        "expires": 9999999999,
    }
    base.update(over)
    return SubagentSession(**base)


def _rpc(method: str, params=None, req_id: int = 1) -> dict:
    msg: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _post(url, payload, headers=None, raw: bytes | None = None, timeout: float = 10):
    body = raw if raw is not None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", _JSON)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict((e.headers or {}).items())


def _raw(port: int, host_value: str, origin: str | None = None,
         payload: dict | list | None = None, raw: bytes | None = None,
         extra: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    if raw is not None:
        body = raw
    else:
        body = json.dumps(payload if payload is not None else _rpc("ping", {})).encode()
    conn.putrequest("POST", "/mcp", skip_host=True)
    conn.putheader("Host", host_value)
    conn.putheader("Content-Type", _JSON)
    conn.putheader("Content-Length", str(len(body)))
    if origin is not None:
        conn.putheader("Origin", origin)
    for k, v in (extra or {}).items():
        conn.putheader(k, v)
    conn.endheaders(body)
    resp = conn.getresponse()
    data = (resp.status, resp.read())
    conn.close()
    return data


def _triple(session: SubagentSession, **over) -> dict:
    h = {
        "Mcp-Session-Id": session.session_id,
        "X-Eca-Audit-Id": session.audit_id,
        "X-Eca-Project-Id": session.project_id,
        "X-Eca-Snapshot-Id": session.snapshot_id,
    }
    h.update(over)
    return h


@pytest.fixture()
def srv():
    server = run("127.0.0.1", 0)
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture()
def auth_srv(monkeypatch):
    monkeypatch.setenv("EMO_G2C_MCP_BEARER", "g2c-s3cret")
    server = run("127.0.0.1", 0, bearer_env_var="EMO_G2C_MCP_BEARER")
    try:
        yield server
    finally:
        server.stop()


# ------------------------------------------------- Host / Origin (5)


def test_wrong_host_403(srv):
    status, _ = _raw(srv.port, "not-allowed.example")
    assert status == 403


def test_dns_rebinding_shape_host_evil_com_403(srv):
    # Classic rebinding: Host pretends to be an attacker domain resolving to 127.0.0.1.
    for evil in ("evil.com", "evil.com:80", "attacker.test", "127.0.0.1.evil.com"):
        status, body = _raw(srv.port, evil)
        assert status == 403, evil
        assert b"forbidden" in body.lower() or b"error" in body.lower()


def test_foreign_origin_403(srv):
    status, _, _ = _post(srv.url, _rpc("ping", {}), {"Origin": "https://evil.example"})
    assert status == 403
    status, _ = _raw(srv.port, "127.0.0.1", origin="http://attacker.test:3000")
    assert status == 403


def test_null_origin_403(srv):
    status, _ = _raw(srv.port, "127.0.0.1", origin="null")
    assert status == 403
    status, _, _ = _post(srv.url, _rpc("ping", {}), {"Origin": "null"})
    assert status == 403


def test_absent_origin_passes(srv):
    status, body, _ = _post(srv.url, _rpc("ping", {}))  # no Origin header at all
    assert status == 200
    assert json.loads(body)["result"] == {}


# ------------------------------------------------- Auth (5)


def test_missing_bearer_401(auth_srv):
    status, _, _ = _post(auth_srv.url, _rpc("ping", {}))
    assert status == 401


def test_wrong_bearer_401(auth_srv):
    status, _, _ = _post(auth_srv.url, _rpc("ping", {}),
                         {"Authorization": "Bearer wrong-token"})
    assert status == 401


@pytest.mark.parametrize("bad", [
    "Token abc123",
    "Bearer",
    "Basic dXNlcjpwYXNz",
    "bearer g2c-s3cret",  # wrong scheme case
    "Bearer  g2c-s3cret ",  # padding shape still must match exactly? checked below
])
def test_malformed_bearer_401(auth_srv, bad):
    if bad == "Bearer  g2c-s3cret ":
        # Double-space / trailing-space: server strips outer whitespace then
        # requires exact "Bearer <secret>"; inner double space must fail.
        status, _, _ = _post(auth_srv.url, _rpc("ping", {}),
                             {"Authorization": bad})
        assert status == 401
        return
    status, _, _ = _post(auth_srv.url, _rpc("ping", {}),
                         {"Authorization": bad})
    assert status == 401


def test_unset_env_var_reference_fails_closed(monkeypatch):
    monkeypatch.delenv("EMO_G2C_MCP_MISSING", raising=False)
    server = run("127.0.0.1", 0, bearer_env_var="EMO_G2C_MCP_MISSING")
    try:
        # Even a plausibly-correct bearer must fail: secret unknown -> closed.
        for hdr in ({"Authorization": "Bearer anything"}, {}):
            status, _, _ = _post(server.url, _rpc("ping", {}), hdr)
            assert status == 401
    finally:
        server.stop()


def test_auth_never_grants_capability_call_still_scope_bound(auth_srv):
    good = {"Authorization": "Bearer g2c-s3cret"}
    # Sanity: valid bearer reaches the dispatcher.
    status, body, _ = _post(auth_srv.url, _rpc("ping", {}), good)
    assert status == 200
    # Scope-bound: cyber_verify with mismatched candidate audit must still be
    # denied INSIDE a 200 result envelope (isError PERMISSION_DENIED), not
    # auto-authorized by the bearer.
    args = {
        "audit_id": "audit-scope-A",
        "candidate": {"audit_id": "audit-scope-B",
                      "hypothesis": "scope probe",
                      "evidence_ids": ["ev1"]},
        "method": "static_confirmation",
        "target": {"kind": "file", "locator": "src/app.py"},
        "rationale": "auth-must-not-grant-capability",
    }
    status, body, _ = _post(
        auth_srv.url, _rpc("tools/call", {"name": "cyber_verify", "arguments": args}), good)
    assert status == 200
    result = json.loads(body)["result"]
    assert result.get("isError") is True
    inner = json.loads(result["content"][0]["text"])
    assert inner["code"] == "PERMISSION_DENIED"
    # Unknown tool is still -32602 inside 200, bearer or not.
    status, body, _ = _post(
        auth_srv.url, _rpc("tools/call", {"name": "no_such_tool", "arguments": {}}), good)
    assert status == 200
    assert json.loads(body)["error"]["code"] == proto.INVALID_PARAMS


# ------------------------------------------------- Payloads (4)


def test_oversized_body_413(srv):
    big = "x" * (proto.MAX_MESSAGE_BYTES + 16)
    status, _, _ = _post(
        srv.url, _rpc("tools/call", {"name": "cyber_status", "arguments": {"pad": big}}))
    assert status == 413


def test_malformed_json_400(srv):
    status, _, _ = _post(srv.url, None, raw=b"{not json")
    assert status == 400
    status, _, _ = _post(srv.url, None, raw=b"\x00\x01\x02")
    assert status == 400


def test_wrong_jsonrpc_version_32600_inside_200(srv):
    bad = {"jsonrpc": "1.0", "id": 7, "method": "ping"}
    status, body, _ = _post(srv.url, bad)
    assert status == 200
    err = json.loads(body)["error"]
    assert err["code"] == -32600
    assert json.loads(body)["id"] == 7


def test_batch_array_32600_inside_200(srv):
    batch = [_rpc("ping", {}, req_id=1), _rpc("ping", {}, req_id=2)]
    status, body, _ = _post(srv.url, batch)
    assert status == 200
    err = json.loads(body)["error"]
    assert err["code"] == -32600


# ------------------------------------------------- Session (4)


def test_session_mismatch_440_plus_quarantine(srv):
    session = _session("mismatch")
    srv.register_session(session, now=int(time.time()))
    bad = _triple(session, **{"X-Eca-Audit-Id": "audit-INTRUDER"})
    status, body, _ = _post(srv.url, _rpc("ping", {}), bad)
    assert status == 440
    data = json.loads(body)
    assert data.get("quarantine") is True
    assert data.get("code") == "MCP_SESSION_MAP_TRIPLE_MISMATCH"
    # Stored chain intact: correct triple still works (never cross-audit).
    status, _, _ = _post(srv.url, _rpc("ping", {}), _triple(session))
    assert status == 200


def test_replay_stale_token_440(srv):
    past = int(time.time()) - 100000
    srv.register_session(_session("stale"), now=past, ttl=60)
    token_headers = _triple(_session("stale"))
    status, body, _ = _post(srv.url, _rpc("ping", {}), token_headers)
    assert status == 440
    assert json.loads(body).get("quarantine") is True
    # Replay: re-presenting the stale token (fresh stale attachment) still
    # quarantines instead of ever dispatching.
    srv.register_session(_session("stale"), now=past, ttl=60)
    status, body, _ = _post(srv.url, _rpc("ping", {}), token_headers)
    assert status == 440
    assert json.loads(body).get("quarantine") is True


def test_unknown_session_token_404(srv):
    status, _, _ = _post(srv.url, _rpc("ping", {}),
                         {"Mcp-Session-Id": "sess-ghost-999"})
    assert status == 404


def test_partial_triple_400(srv):
    session = _session("partial")
    srv.register_session(session, now=int(time.time()))
    partial = {"Mcp-Session-Id": session.session_id,
               "X-Eca-Audit-Id": session.audit_id}  # missing 2 of 3
    status, _, _ = _post(srv.url, _rpc("ping", {}), partial)
    assert status == 400


# ------------------------------------------------- Slow request (1)


def test_slow_incomplete_request_bounded_server_stays_responsive(srv):
    start = time.monotonic()
    raw = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    try:
        raw.settimeout(5)
        # Slowloris shape: partial body, stall, then abandon.
        raw.sendall(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    b"Content-Length: 64\r\nContent-Type: application/json\r\n\r\n{")
        time.sleep(0.5)
    finally:
        try:
            raw.close()
        except OSError:
            pass
    stall_setup = time.monotonic() - start
    assert stall_setup < 5, f"slow-request setup hung: {stall_setup:.2f}s"
    time.sleep(0.3)
    # Server must still answer promptly afterwards.
    start = time.monotonic()
    status, body, _ = _post(srv.url, _rpc("ping", {}), timeout=5)
    elapsed = time.monotonic() - start
    assert status == 200
    assert json.loads(body)["result"] == {}
    assert elapsed < 5, f"server unresponsive after slow request: {elapsed:.2f}s"


# ------------------------------------------------- Concurrency (1)


def test_concurrent_rapid_calls_no_crosstalk(srv):
    sess_a = _session("conca")
    sess_b = _session("concb")
    srv.register_session(sess_a, now=int(time.time()))
    srv.register_session(sess_b, now=int(time.time()))

    def _call(session: SubagentSession, i: int):
        status, body, echo = _post(
            srv.url, _rpc("ping", {}, req_id=i), _triple(session), timeout=10)
        echoed = {k.lower(): v for k, v in echo.items()}.get("mcp-session-id")
        return status, body, echoed

    jobs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        for i in range(24):
            jobs.append(pool.submit(_call, sess_a if i % 2 == 0 else sess_b, i))
        results = [f.result(timeout=15) for f in jobs]
    for i, (status, body, echoed) in enumerate(results):
        assert status == 200, f"job {i} got {status}"
        assert json.loads(body)["result"] == {}
        want = sess_a.session_id if i % 2 == 0 else sess_b.session_id
        assert echoed == want, f"cross-talk on job {i}: {echoed!r} != {want!r}"
    # A wrong-triple request during/after the storm still quarantines cleanly.
    bad = _triple(sess_a, **{"X-Eca-Audit-Id": "audit-INTRUDER"})
    status, body, _ = _post(srv.url, _rpc("ping", {}), bad)
    assert status == 440
    assert json.loads(body).get("quarantine") is True
    status, _, _ = _post(srv.url, _rpc("ping", {}), _triple(sess_b))
    assert status == 200
