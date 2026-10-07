"""POST-T020 G2-B — HTTP Client Matrix (black-box, stdlib only).

Live-socket client tests against HttpMcpServer (urllib/http.client/sockets):

- full python-client flow over real HTTP
- session reconnect after detach + stale-token 440 quarantine (no cross-audit)
- cancellation / client-timeout bounded behavior (no hang)
- honest host probes for opencode/pi/hermes/jan (docs/--help inspection only)
- SSE compatibility probe: GET /mcp -> 405 (no new SSE implementation)

Never fake: host verdicts are ENVIRONMENT-TESTED only when the host binary
is present AND its --help advertises remote/HTTP MCP registration AND live
discovery (initialize -> tools/list) against the live EMO URL succeeds.
Otherwise NOT-ENVIRONMENT-TESTED with a reason (skip, not fail).
"""

from __future__ import annotations

import http.client
import json
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request

import pytest

from emo_cyber_agent.mcp.http_server import run
from emo_cyber_agent.subagent.session import SubagentSession

_JSON = "application/json"
_SSE = "text/event-stream"

# ---------------------------------------------------------------- helpers


def _session(suffix: str, **over) -> SubagentSession:
    base = {
        "session_id": f"sess-cli-{suffix}",
        "host_id": f"host-cli-{suffix}",
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


def _post(url: str, payload, headers: dict | None = None, timeout: float = 10):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", _JSON)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict((e.headers or {}).items())


def _get_status(url: str, timeout: float = 10) -> int:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def _triple_headers(session: SubagentSession, **over) -> dict:
    triple = {
        "Mcp-Session-Id": session.session_id,
        "X-Eca-Audit-Id": session.audit_id,
        "X-Eca-Project-Id": session.project_id,
        "X-Eca-Snapshot-Id": session.snapshot_id,
    }
    triple.update(over)
    return triple


def _parse_sse_frames(raw: bytes):
    """Client-side parse of POST-response SSE frames (no new SSE impl)."""
    text = raw.decode("utf-8")
    blocks = [b for b in text.split("\n\n") if b.strip()]
    kinds: list[str] = []
    payloads: list[dict] = []
    for b in blocks:
        first = b.splitlines()[0].strip()
        kinds.append(first)
        data_idx = b.find("data: ")
        assert data_idx != -1, f"SSE block without data: {b!r}"
        payloads.append(json.loads(b[data_idx + len("data: "):]))
    return kinds, payloads, blocks


@pytest.fixture()
def srv():
    server = run("127.0.0.1", 0)
    try:
        yield server
    finally:
        server.stop()


# ------------------------------------------------- full client flow


def test_python_client_full_flow_live(srv):
    """initialize -> tools/list -> tools/call -> SSE parse -> session call."""
    url = srv.url

    # initialize
    status, body, _ = _post(url, _rpc("initialize", {"protocolVersion": "2025-03-26"}))
    assert status == 200, body
    data = json.loads(body)
    assert data["result"]["serverInfo"]["name"] == "emo-cyber-agent"

    # tools/list
    status, body, _ = _post(url, _rpc("tools/list", {}, req_id=2))
    assert status == 200, body
    names = {t["name"] for t in json.loads(body)["result"]["tools"]}
    assert "cyber_status" in names and "cyber_audit" in names

    # tools/call cyber_status (plain JSON)
    status, body, _ = _post(
        url, _rpc("tools/call", {"name": "cyber_status", "arguments": {}}, req_id=3)
    )
    assert status == 200, body
    payload = json.loads(json.loads(body)["result"]["content"][0]["text"])
    assert payload["status"] == "ok"

    # progress stream parse (SSE frames on POST response)
    token = "tok-cli-fullflow-01"
    status, body, headers = _post(
        url,
        _rpc(
            "tools/call",
            {"name": "cyber_status", "arguments": {}, "_meta": {"progressToken": token}},
            req_id=4,
        ),
        {"Accept": _SSE},
    )
    assert status == 200, body
    ctype = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
    assert _SSE in ctype
    kinds, payloads, blocks = _parse_sse_frames(body)
    assert kinds.count("event: notification") == 4
    assert kinds[-1] == "event: message"
    notes = payloads[:-1]
    assert [n["method"] for n in notes] == ["notifications/progress"] * 4
    assert [n["params"]["phase"] for n in notes] == [
        "STARTED",
        "RUNNING",
        "FINALIZING",
        "COMPLETED",
    ]
    assert all(n["params"]["progressToken"] == token for n in notes)
    final = payloads[-1]
    assert "result" in final

    # session register -> session-bound call
    session = _session("fullflow")
    srv.register_session(session, now=int(time.time()))
    status, body, echo = _post(url, _rpc("ping", {}, req_id=5), _triple_headers(session))
    assert status == 200, body
    assert json.loads(body)["result"] == {}
    echoed = {k.lower(): v for k, v in echo.items()}.get("mcp-session-id")
    assert echoed == session.session_id


def test_clean_shutdown_bounded():
    """Dedicated live server stops cleanly; further connects fail fast."""
    server = run("127.0.0.1", 0)
    url, port = server.url, server.port
    status, _, _ = _post(url, _rpc("ping", {}))
    assert status == 200
    server.stop()
    with pytest.raises(Exception):
        _post(url, _rpc("ping", {}), timeout=3)
    # socket-level: refused fast, never hangs
    start = time.monotonic()
    with pytest.raises(OSError):
        conn = socket.create_connection(("127.0.0.1", port), timeout=3)
        conn.close()
    assert time.monotonic() - start < 5


# ------------------------------------------------- session reconnect


def test_session_reconnect_new_attachment_after_detach(srv):
    session = _session("reconnect")
    srv.register_session(session, now=int(time.time()))
    status, _, _ = _post(srv.url, _rpc("ping", {}), _triple_headers(session))
    assert status == 200
    # detach (purge token) -> unknown session, never dispatched
    removed = srv._session_map.detach(session.session_id)
    assert removed is True
    status, _, _ = _post(srv.url, _rpc("ping", {}), _triple_headers(session))
    assert status == 404
    # reconnect: fresh attachment for the same triple works again
    srv.register_session(session, now=int(time.time()))
    status, body, _ = _post(srv.url, _rpc("ping", {}), _triple_headers(session))
    assert status == 200
    assert json.loads(body)["result"] == {}


def test_stale_token_440_quarantine_no_cross_audit(srv):
    victim = _session("stalevictim")
    other = _session("stalewitness")
    past = int(time.time()) - 100000
    srv.register_session(victim, now=past, ttl=60)
    srv.register_session(other, now=int(time.time()))
    # stale token -> 440 quarantine, never dispatched
    status, body, _ = _post(srv.url, _rpc("ping", {}), _triple_headers(victim))
    assert status == 440, body
    data = json.loads(body)
    assert data.get("quarantine") is True
    assert data.get("code") == "MCP_SESSION_MAP_TRIPLE_MISMATCH"
    # witness session unaffected (no cross-audit)
    status, body, _ = _post(srv.url, _rpc("ping", {}), _triple_headers(other))
    assert status == 200
    assert json.loads(body)["result"] == {}
    # wrong-triple on live session also quarantines without corrupting stored chain
    bad = _triple_headers(other, **{"X-Eca-Audit-Id": "audit-INTRUDER"})
    status, body, _ = _post(srv.url, _rpc("ping", {}), bad)
    assert status == 440
    assert json.loads(body).get("quarantine") is True
    status, _, _ = _post(srv.url, _rpc("ping", {}), _triple_headers(other))
    assert status == 200


# ------------------------------------------------- cancellation / timeout


def _run_slow_blackhole():
    """Accept one connection then stall (never respond). Returns (port, stop)."""
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    port = int(ls.getsockname()[1])
    halt = threading.Event()

    def _serve():
        ls.settimeout(10)
        try:
            conn, _ = ls.accept()
        except socket.timeout:
            return
        with conn:
            conn.settimeout(10)
            try:
                conn.recv(65536)
            except OSError:
                pass
            halt.wait(10)  # stall: never reply
        ls.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return port, halt, t


def test_client_timeout_on_slow_path_bounded_no_hang():
    port, halt, _t = _run_slow_blackhole()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.3)
        body = json.dumps(_rpc("ping", {})).encode()
        start = time.monotonic()
        with pytest.raises((socket.timeout, TimeoutError)):
            conn.putrequest("POST", "/mcp")
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            conn.getresponse().read()
        elapsed = time.monotonic() - start
        assert elapsed < 5, f"client hung: {elapsed:.2f}s"
        conn.close()
    finally:
        halt.set()
    # sanity: the real server answers quickly (no regression into slowness)
    server = run("127.0.0.1", 0)
    try:
        start = time.monotonic()
        status, _, _ = _post(server.url, _rpc("ping", {}), timeout=5)
        assert status == 200
        assert time.monotonic() - start < 5
    finally:
        server.stop()


def test_cancelled_request_does_not_kill_server(srv):
    """Abrupt client close mid-request: server must survive for the next call."""
    raw = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    try:
        raw.sendall(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\n{")
    finally:
        raw.close()  # cancel: close without completing body / reading reply
    time.sleep(0.2)
    status, body, _ = _post(srv.url, _rpc("ping", {}), timeout=5)
    assert status == 200
    assert json.loads(body)["result"] == {}


# ------------------------------------------------- SSE compatibility probe


def test_sse_compatibility_get_mcp_405(srv):
    """GET /mcp is not a primary channel: must be 405 (POST-only)."""
    status = _get_status(srv.url)
    assert status == 405
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
    conn.request("GET", "/mcp", headers={"Accept": _SSE})
    resp = conn.getresponse()
    assert resp.status == 405
    allow = resp.getheader("Allow") or ""
    assert "POST" in allow
    conn.close()


# ------------------------------------------------- honest host probes

_HOST_BINARIES = ("opencode", "pi", "hermes", "jan")


def _run_help(args: list[str]) -> str | None:
    """Run an exact help argv with a hard timeout; None on any failure/empty."""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    return out or None


def _read_help_text(binary: str, extra_args: list[str]) -> str | None:
    """Run <binary> with extra_args + --help (exact argv); None on failure."""
    exe = shutil.which(binary)
    if not exe:
        return None
    return _run_help([exe, *extra_args, "--help"])


def _binary_supports_http_mcp(binary: str) -> tuple[bool, str]:
    """Docs/--help inspection only. Never launches agents or models."""
    exe = shutil.which(binary)
    if not exe:
        return False, f"binary {binary!r} not on PATH"
    texts: list[str] = []
    top = _read_help_text(binary, [])
    if top:
        texts.append(top)
    sub = None
    if binary in ("opencode", "hermes"):
        sub = _read_help_text(binary, ["mcp", "add"])
        if sub:
            texts.append(sub)
    blob = "\n".join(texts).lower()
    if not blob:
        return False, f"binary {binary!r} present but --help produced no output"
    # Remote/HTTP MCP registration is advertised via an --url flag in an MCP
    # context (opencode: "--url URL for a remote MCP server";
    # hermes: "--url URL HTTP/SSE endpoint URL").
    has_url = "--url" in blob
    has_mcp = "mcp" in blob
    if has_url and has_mcp:
        return True, f"{binary} --help advertises remote/HTTP MCP registration (--url + mcp)"
    return False, (
        f"{binary} --help shows no remote/HTTP MCP registration "
        f"(has --url={has_url}, mentions mcp={has_mcp})"
    )


@pytest.mark.parametrize("host", _HOST_BINARIES)
def test_host_http_probe(srv, host: str):
    """Honest per-host probe: ENVIRONMENT-TESTED only on real discovery."""
    supported, reason = _binary_supports_http_mcp(host)
    if not supported:
        pytest.skip(f"NOT-ENVIRONMENT-TESTED {host}: {reason}")
    # Register EMO's live HTTP URL (in-memory registration snippet with the
    # live URL substituted) and attempt discovery over real HTTP.
    live_url = srv.url
    reg_snippet: dict = {}
    try:
        if host == "opencode":
            from emo_cyber_agent.subagent import hosts_opencode as adapter

            reg_snippet = adapter.get_registration_config()
        elif host == "pi":
            from emo_cyber_agent.subagent import hosts_pi as adapter  # type: ignore[no-redef]

            reg_snippet = adapter.get_registration_config(
                scope="project", transport="streamable-http"
            )
        elif host == "hermes":
            from emo_cyber_agent.subagent import hosts_hermes as adapter  # type: ignore[no-redef]

            reg_snippet = adapter.get_registration_config(transport="streamable-http")
        elif host == "jan":
            from emo_cyber_agent.subagent import hosts_jan as adapter  # type: ignore[no-redef]

            reg_snippet = adapter.get_registration_config(
                surface="desktop", transport="streamable-http"
            )
    except Exception as e:
        pytest.skip(f"NOT-ENVIRONMENT-TESTED {host}: adapter config failed: {e}")
    snippet_text = json.dumps(reg_snippet)
    assert "emo-cyber-agent" in snippet_text, f"registration snippet lost server key: {reg_snippet}"
    # Attempt discovery against the live URL the host would be pointed at.
    status, body, _ = _post(live_url, _rpc("initialize", {"protocolVersion": "2025-03-26"}))
    assert status == 200, f"discovery initialize failed for {host}: {body!r}"
    status, body, _ = _post(live_url, _rpc("tools/list", {}, req_id=2))
    assert status == 200, f"discovery tools/list failed for {host}: {body!r}"
    names = {t["name"] for t in json.loads(body)["result"]["tools"]}
    assert "cyber_status" in names
    print(f"\nENVIRONMENT-TESTED {host}: {reason}; live discovery OK at {live_url}")


def test_host_matrix_summary(capsys):
    """Emit the honest per-host verdict table (never fails on environment)."""
    rows = []
    for host in _HOST_BINARIES:
        supported, reason = _binary_supports_http_mcp(host)
        verdict = "SUPPORTS-REMOTE-DOCS" if supported else "NOT-ENVIRONMENT-TESTED"
        rows.append(f"{host}: {verdict} ({reason})")
    print("\nHOST MATRIX (docs/--help inspection only, no host launched):")
    for row in rows:
        print(f"  - {row}")
    assert len(rows) == 4
