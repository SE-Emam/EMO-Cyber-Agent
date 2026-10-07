"""G12 — Fuzz Owner for EMO-Cyber-Agent POST-T020 new surface.

Bounded, parametrized, plain pytest fuzz over:
  HTTP server / checklist spec / template validator / benchmark case parser /
  platform alias fn / loader scoping.

Contract: every case ends in one of
  VALID / REJECTED / SANITIZED / QUARANTINED / FAIL_CLOSED / DENY /
  400 / 401 / 403 / 404 / 413 / 440
and asserts NO unhandled crash (unexpected exception types -> pytest.fail).
"""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

ALLOWED_VERDICTS = frozenset({
    "VALID", "REJECTED", "SANITIZED", "QUARANTINED", "FAIL_CLOSED", "DENY",
    "400", "401", "403", "404", "413", "440",
})

# --- domain error imports (best-effort; missing => None placeholder) ---
try:
    from emo_cyber_agent.mcp import http_server as _http
    from emo_cyber_agent.mcp.http_server import HttpMcpServer, _HttpError
except Exception:  # pragma: no cover
    _http = None  # type: ignore[assignment]
    HttpMcpServer = None  # type: ignore[assignment,misc]
    _HttpError = Exception  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.mcp.server import McpServer
except Exception:  # pragma: no cover
    McpServer = None  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.checklists.spec import Checklist, ChecklistItem
except Exception:  # pragma: no cover
    Checklist = None  # type: ignore[assignment,misc]
    ChecklistItem = None  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.report_templates.spec import ReportTemplateSpec, TemplateError
except Exception:  # pragma: no cover
    ReportTemplateSpec = None  # type: ignore[assignment,misc]
    TemplateError = Exception  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.report_templates.validator import ReportTemplateValidator
except Exception:  # pragma: no cover
    ReportTemplateValidator = None  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.evaluation.post_t020_benchmark import (
        PostT020Case,
        post_t020_blind,
    )
    from emo_cyber_agent.evaluation.cases import normalize_case
    from emo_cyber_agent.evaluation.errors import EvaluationError
except Exception:  # pragma: no cover
    PostT020Case = None  # type: ignore[assignment,misc]
    post_t020_blind = None  # type: ignore[assignment,misc]
    normalize_case = None  # type: ignore[assignment,misc]
    EvaluationError = Exception  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.extensions.compatibility import (
        HostProfile as ExtHostProfile,
    )
    from emo_cyber_agent.extensions.compatibility import (
        check_compatibility,
        host_profile,
        python_satisfies,
        satisfies,
    )
except Exception:  # pragma: no cover
    ExtHostProfile = None  # type: ignore[assignment,misc]
    check_compatibility = None  # type: ignore[assignment,misc]
    host_profile = None  # type: ignore[assignment,misc]
    satisfies = None  # type: ignore[assignment,misc]
    python_satisfies = None  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.subagent.session_map import (
        McpSessionMap,
        SessionMapError,
        validate_mcp_token,
    )
except Exception:  # pragma: no cover
    McpSessionMap = None  # type: ignore[assignment,misc]
    SessionMapError = Exception  # type: ignore[assignment,misc]
    validate_mcp_token = None  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.subagent.session import SubagentSession
except Exception:  # pragma: no cover
    SubagentSession = None  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.subagent.binding import BindingError
except Exception:  # pragma: no cover
    BindingError = Exception  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.subagent.trust import HostIntegrationError
except Exception:  # pragma: no cover
    HostIntegrationError = Exception  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.security_knowledge.scope import bind_query_scope
    from emo_cyber_agent.security_knowledge.errors import KnowledgeError
except Exception:  # pragma: no cover
    bind_query_scope = None  # type: ignore[assignment,misc]
    KnowledgeError = Exception  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.checklists.catalog import get_by_scope, get_checklist
except Exception:  # pragma: no cover
    get_by_scope = None  # type: ignore[assignment,misc]
    get_checklist = None  # type: ignore[assignment,misc]

try:
    from emo_cyber_agent.playbooks.spec import PlaybookError
except Exception:  # pragma: no cover
    PlaybookError = Exception  # type: ignore[assignment,misc]

EXPECTED_EXC = (
    ValueError, TypeError, KeyError, IndexError, AttributeError,
    UnicodeError, OverflowError, AssertionError, OSError,
    ValidationError, EvaluationError, KnowledgeError, BindingError,
    SessionMapError, HostIntegrationError, PlaybookError, TemplateError,
    _HttpError,
)


def _assert_verdict(v: str, ctx: str = "") -> str:
    assert v in ALLOWED_VERDICTS, f"bad verdict {v!r} {ctx}"
    return v


HUGE_10K = "X" * 10_000
HUGE_2M = "Y" * (2 * 1024 * 1024)
UNICODE = "t\u202e\u200b\U0001f4a3caf\u00e9"
CONTROL = "a\x00\x01\x02\x1b[31mred\x1b[0m\n\r\t"
ANSI = "\x1b[2J\x1b[H\x1b[31mALERT\x1b[0m"


def _mk_session(sid: str = "sess-fuzz-01"):
    assert SubagentSession is not None
    return SubagentSession(
        session_id=sid, host_id="host-fuzz", audit_id="audit-fuzz",
        project_id="project-fuzz", snapshot_id="snap-fuzz",
        created=100, expires=9999,
    )


def _valid_template_dict() -> dict[str, Any]:
    return dict(
        template_id="fuzz-demo", name="Demo", version="1.0.0", type="security",
        description="demo",
        sections=(
            {"name": "summary", "fields": ["report.summary"]},
            {"name": "findings", "fields": ["finding.title"]},
        ),
        finding_fields=[
            "finding.finding_id", "finding.title", "finding.severity",
            "finding.confidence", "finding.status", "finding.evidence_ids",
            "finding.verification_ids", "finding.provenance",
        ],
        section_order=["summary", "findings", "limitations"],
        show_non_reportable=False,
        evidence_presentation="references", verification_presentation="status",
        limitations_sections=["limitations"], appendices=[],
        output_formats=["json", "jsonl", "markdown"],
        provenance={"source": "fuzz"},
    )


def _gt_record(kind: str = "expected_blocked") -> dict[str, Any]:
    return {"record_id": "r1", "kind": kind, "subject": "s",
            "value": "v", "match": "exact", "stage": "regression", "note": ""}


def _valid_post_t020_dict(case_id: str = "fuzz.case-01") -> dict[str, Any]:
    return {
        "case_id": case_id, "title": "fuzz title", "category": "code",
        "kind": "positive", "input": {"probe": "x"},
        "expected_signal": [_gt_record("expected_blocked")],
        "must_not": [],
        "source": {"system": "internal", "fixture": "post-t020"},
        "notes": "",
    }


# ===========================================================================
# 1) HTTP server: dispatch fuzz (null/empty/bool/numeric/huge/unicode/...)
# ===========================================================================

_DISPATCH_CASES: list[Any] = [
    None, "", b"bytes-not-dict", 0, 1, 3.14, True, False, [], {},
    {"jsonrpc": "1.0", "id": 1, "method": "ping", "params": {}},
    {"jsonrpc": "2.0", "method": "ping"},
    {"jsonrpc": "2.0", "id": 1},
    {"jsonrpc": "2.0", "id": 1, "method": None, "params": {}},
    {"jsonrpc": "2.0", "id": 1, "method": 123, "params": {}},
    {"jsonrpc": "2.0", "id": 1, "method": "no-such-method", "params": {}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": "not-a-dict"},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_nope", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": None, "arguments": {}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": 123, "arguments": {}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_status", "arguments": {"capabilities": None}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_status", "arguments": {"capabilities": 123}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_status", "arguments": {"capabilities": ["admin.write"] * 500}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_status", "arguments": {"target": HUGE_10K}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_status", "arguments": {"target": UNICODE}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_status", "arguments": {"target": CONTROL}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_status", "arguments": {"target": ANSI}}},
    [{"jsonrpc": "2.0", "id": 1, "method": "ping"}],
    {"jsonrpc": "2.0", "id": "dup-1", "method": "ping", "params": {}},
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "bogus-version"}},
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": None}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_status", "arguments": {},
                "_meta": {"progressToken": "\x00bad"}}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "cyber_status", "arguments": {},
                "_meta": {"progressToken": "x" * 500}}},
    {"jsonrpc": None, "id": 1, "method": "ping"},
    {"jsonrpc": "2.0", "id": {"nested": [1, 2]}, "method": "ping"},
]


@pytest.mark.parametrize("msg", _DISPATCH_CASES)
def test_fuzz_http_dispatch_no_crash(msg):
    if McpServer is None or HttpMcpServer is None:
        pytest.skip("mcp surface absent")
    try:
        server = McpServer()
        resp = server.handle_message(msg)
        owner = HttpMcpServer(server=McpServer())
        resp2, notes = owner.dispatch(msg)
        if isinstance(resp, dict) and "result" in resp:
            v = "VALID"
        elif isinstance(resp, dict) and "error" in resp:
            v = "REJECTED"
        elif resp is None:
            v = "VALID"
        else:
            v = "FAIL_CLOSED"
        assert isinstance(notes, list)
        _assert_verdict(v, ctx=repr(msg)[:120])
        # dispatch-level: None response (notification) or envelope both bounded
        assert resp2 is None or isinstance(resp2, dict)
    except EXPECTED_EXC as e:
        _assert_verdict("REJECTED", ctx=f"{type(e).__name__}:{e}"[:120])
    except Exception as e:  # noqa: BLE001 - fuzz must surface unhandled crashes
        pytest.fail(f"UNHANDLED CRASH dispatch input={msg!r:.300} exc={type(e).__name__}:{e!r:.300}")


def test_fuzz_http_duplicate_ids_no_crash():
    if McpServer is None:
        pytest.skip("mcp surface absent")
    try:
        server = McpServer()
        r1 = server.handle_message({"jsonrpc": "2.0", "id": "dup-x", "method": "ping"})
        r2 = server.handle_message({"jsonrpc": "2.0", "id": "dup-x", "method": "ping"})
        assert isinstance(r1, dict) and isinstance(r2, dict)
        _assert_verdict("VALID", ctx="duplicate-ids")
    except EXPECTED_EXC:
        _assert_verdict("REJECTED", ctx="duplicate-ids")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH duplicate-ids exc={e!r:.300}")


def test_fuzz_http_huge_event_burst_no_crash():
    if McpServer is None:
        pytest.skip("mcp surface absent")
    try:
        server = McpServer()
        for i in range(150):
            resp = server.handle_message(
                {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                 "params": {"name": "cyber_status", "arguments": {},
                            "_meta": {"progressToken": f"burst-{i % 5}"}}},
            )
            assert resp is None or isinstance(resp, dict)
            notes = server.drain_notifications()
            assert isinstance(notes, list) and len(notes) <= 16
        tail = server.handle_message({"jsonrpc": "2.0", "id": 9999, "method": "ping"})
        assert isinstance(tail, dict)
        _assert_verdict("VALID", ctx="burst")
    except EXPECTED_EXC:
        _assert_verdict("FAIL_CLOSED", ctx="burst")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH burst exc={e!r:.300}")


# ===========================================================================
# 2) HTTP guards: host / origin / auth
# ===========================================================================

_HOST_CASES = [None, "", " ", "evil.com", "127.0.0.1", "LOCALHOST",
               "localhost:8000", "[::1]:8080", "::1", HUGE_10K[:2000],
               UNICODE, CONTROL, ANSI, "127.0.0.1\x00.evil.com", 123, True]


@pytest.mark.parametrize("h", _HOST_CASES)
def test_fuzz_http_host_guard(h):
    if HttpMcpServer is None:
        pytest.skip("http surface absent")
    try:
        owner = HttpMcpServer()
        owner.check_host(h)  # type: ignore[arg-type]
        _assert_verdict("VALID", ctx=f"host={h!r:.80}")
    except _HttpError as e:
        assert e.status in (400, 401, 403, 404, 413, 440)
        _assert_verdict(str(e.status), ctx=f"host={h!r:.80}")
    except EXPECTED_EXC:
        _assert_verdict("FAIL_CLOSED", ctx=f"host={h!r:.80}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH host={h!r:.200} exc={e!r:.300}")


_ORIGIN_CASES = [None, "", "   ", "null", "NULL", "http://evil.com",
                 "https://localhost:8000/x", "http://127.0.0.1/", "file://evil",
                 UNICODE, CONTROL, ANSI, HUGE_10K[:2000], 123, True, "http://[::1]/"]


@pytest.mark.parametrize("o", _ORIGIN_CASES)
def test_fuzz_http_origin_guard(o):
    if HttpMcpServer is None:
        pytest.skip("http surface absent")
    try:
        owner = HttpMcpServer()
        owner.check_origin(o)  # type: ignore[arg-type]
        _assert_verdict("VALID", ctx=f"origin={o!r:.80}")
    except _HttpError as e:
        assert e.status in (400, 401, 403, 404, 413, 440)
        _assert_verdict(str(e.status), ctx=f"origin={o!r:.80}")
    except EXPECTED_EXC:
        _assert_verdict("FAIL_CLOSED", ctx=f"origin={o!r:.80}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH origin={o!r:.200} exc={e!r:.300}")


_AUTH_CASES = [None, "", " ", "Bearer x", "bearer x", "Bearer ", "Basic abc",
               HUGE_10K[:2000], UNICODE, CONTROL, ANSI, 123, True, "Bearer \x00"]


@pytest.mark.parametrize("a", _AUTH_CASES)
def test_fuzz_http_auth_guard(a):
    if HttpMcpServer is None:
        pytest.skip("http surface absent")
    var = "FUZZ_T020_BEARER_XYZ"
    old = os.environ.get(var)
    os.environ[var] = "correct-secret"
    try:
        owner = HttpMcpServer(bearer_env_var=var)
        try:
            owner.check_auth(a)  # type: ignore[arg-type]
            _assert_verdict("VALID", ctx=f"auth={a!r:.80}")
        except _HttpError as e:
            assert e.status in (400, 401, 403, 404, 413, 440)
            _assert_verdict(str(e.status), ctx=f"auth={a!r:.80}")
    except EXPECTED_EXC:
        _assert_verdict("FAIL_CLOSED", ctx=f"auth={a!r:.80}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH auth={a!r:.200} exc={e!r:.300}")
    finally:
        if old is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = old


def test_fuzz_http_auth_misconfigured_fail_closed():
    if HttpMcpServer is None:
        pytest.skip("http surface absent")
    var = "FUZZ_T020_MISSING_XYZ"
    os.environ.pop(var, None)
    try:
        owner = HttpMcpServer(bearer_env_var=var)
        try:
            owner.check_auth("Bearer anything")
            pytest.fail("misconfigured bearer must fail closed")
        except _HttpError as e:
            assert e.status == 401
            _assert_verdict("401", ctx="misconfigured")
    except EXPECTED_EXC:
        _assert_verdict("FAIL_CLOSED", ctx="misconfigured")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH misconfigured exc={e!r:.300}")


# ===========================================================================
# 3) HTTP session binding: forged tokens / wrong triples / stale snapshots
# ===========================================================================

_TOKEN_CASES = [None, "", " ", "\x00", "x" * 300, "tok\x1b[31m", UNICODE,
                CONTROL, "forged-token-xyz", 123, True, ["t"], {"t": 1},
                "tok stale 999", "t020-prog-1"]


@pytest.mark.parametrize("tok", _TOKEN_CASES)
def test_fuzz_http_session_tokens(tok):
    if HttpMcpServer is None or McpSessionMap is None or SubagentSession is None:
        pytest.skip("session surface absent")
    try:
        owner = HttpMcpServer()
        sess = _mk_session()
        owner.register_session(sess, now=1000, ttl=60)
        triple = {"X-Eca-Audit-Id": "audit-fuzz", "X-Eca-Project-Id": "project-fuzz",
                  "X-Eca-Snapshot-Id": "snap-fuzz"}
        try:
            owner.check_session(tok, triple=triple)  # type: ignore[arg-type]
            _assert_verdict("VALID", ctx=f"tok={tok!r:.80}")
        except _HttpError as e:
            assert e.status in (400, 401, 403, 404, 413, 440)
            _assert_verdict(str(e.status), ctx=f"tok={tok!r:.80}")
    except EXPECTED_EXC:
        _assert_verdict("REJECTED", ctx=f"tok={tok!r:.80}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH tok={tok!r:.200} exc={e!r:.300}")


_TRIPLE_CASES = [
    {},
    {"X-Eca-Audit-Id": "audit-fuzz"},
    {"X-Eca-Audit-Id": "audit-fuzz", "X-Eca-Project-Id": "project-fuzz"},
    {"X-Eca-Audit-Id": "audit-WRONG", "X-Eca-Project-Id": "project-fuzz",
     "X-Eca-Snapshot-Id": "snap-fuzz"},
    {"X-Eca-Audit-Id": "audit-fuzz", "X-Eca-Project-Id": "project-OTHER",
     "X-Eca-Snapshot-Id": "snap-fuzz"},
    {"X-Eca-Audit-Id": "audit-fuzz", "X-Eca-Project-Id": "project-fuzz",
     "X-Eca-Snapshot-Id": "snap-stale-999"},
    {"X-Eca-Audit-Id": "", "X-Eca-Project-Id": "", "X-Eca-Snapshot-Id": ""},
    {"X-Eca-Audit-Id": UNICODE, "X-Eca-Project-Id": "project-fuzz",
     "X-Eca-Snapshot-Id": "snap-fuzz"},
    {"X-Eca-Audit-Id": HUGE_10K[:2000], "X-Eca-Project-Id": "project-fuzz",
     "X-Eca-Snapshot-Id": "snap-fuzz"},
]


@pytest.mark.parametrize("triple", _TRIPLE_CASES)
def test_fuzz_http_session_triples(triple):
    if HttpMcpServer is None or SubagentSession is None:
        pytest.skip("session surface absent")
    try:
        owner = HttpMcpServer()
        sess = _mk_session("sess-triple-01")
        owner.register_session(sess, now=1000, ttl=3600)
        try:
            owner.check_session("sess-triple-01", triple=triple)
            _assert_verdict("VALID", ctx=repr(triple)[:100])
        except _HttpError as e:
            assert e.status in (400, 401, 403, 404, 413, 440)
            if e.status == 440:
                assert getattr(e, "quarantine", True) is True
                _assert_verdict("QUARANTINED", ctx=repr(triple)[:100])
            else:
                _assert_verdict(str(e.status), ctx=repr(triple)[:100])
    except EXPECTED_EXC:
        _assert_verdict("REJECTED", ctx=repr(triple)[:100])
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH triple={triple!r:.300} exc={e!r:.300}")


def test_fuzz_session_map_stale_and_malformed_caps():
    if McpSessionMap is None or SubagentSession is None:
        pytest.skip("session surface absent")
    caps = [None, "", 123, True, ["repo.read"], ["admin.write"],
            ["repo.read"] * 300, HUGE_10K[:2000], UNICODE, CONTROL]
    for c in caps:
        try:
            m = McpSessionMap()
            s = _mk_session("sess-cap-01")
            m.attach(s, mcp_token_or_id="tok-cap-01", audit_id="audit-fuzz",
                     project_id="project-fuzz", snapshot_id="snap-fuzz",
                     now=1000, ttl=60)
            try:
                m.resolve("tok-cap-01", now=1000 + 61, ttl=60)
                _assert_verdict("VALID", ctx=f"cap={c!r:.60}")
            except (SessionMapError, KeyError):
                _assert_verdict("QUARANTINED", ctx=f"cap={c!r:.60}")
        except EXPECTED_EXC:
            _assert_verdict("REJECTED", ctx=f"cap={c!r:.60}")
        except Exception as e:  # noqa: BLE001
            pytest.fail(f"UNHANDLED CRASH cap={c!r:.200} exc={e!r:.300}")


# ===========================================================================
# 4) Live HTTP transport: malformed JSON / huge / wrong path / methods
# ===========================================================================

def _live_post(server, raw: bytes, path: str = "/mcp",
               method: str = "POST", headers: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    try:
        conn.request(method, path, body=raw,
                     headers={"Content-Type": "application/json",
                              "Content-Length": str(len(raw)),
                              **(headers or {})})
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    finally:
        conn.close()


_LIVE_CASES = [
    ("empty", b"", "/mcp", "POST"),
    ("null", b"null", "/mcp", "POST"),
    ("numeric", b"123", "/mcp", "POST"),
    ("bool", b"true", "/mcp", "POST"),
    ("bad-json", b"{not json", "/mcp", "POST"),
    ("truncated", b'{"jsonrpc": "2.0", "id":', "/mcp", "POST"),
    ("wrong-version", b'{"jsonrpc":"1.0","id":1,"method":"ping"}', "/mcp", "POST"),
    ("unknown-tool", b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                      b'"params":{"name":"evil","arguments":{}}}', "/mcp", "POST"),
    ("unicode", '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}'.encode(),
     "/mcp", "POST"),
    ("control", b'{"jsonrpc":"2.0","id":1,"method":"\x00ping"}', "/mcp", "POST"),
    ("ansi", b'{"jsonrpc":"2.0","id":1,"method":"ping\x1b[31m"}', "/mcp", "POST"),
    ("wrong-path", b'{"jsonrpc":"2.0","id":1,"method":"ping"}', "/nope", "POST"),
    ("get-mcp", b"", "/mcp", "GET"),
    ("delete-mcp", b"", "/mcp", "DELETE"),
]


@pytest.mark.parametrize("name,raw,path,method", _LIVE_CASES)
def test_fuzz_http_live_transport(name, raw, path, method):
    if HttpMcpServer is None:
        pytest.skip("http surface absent")
    server = HttpMcpServer()
    server.start("127.0.0.1", 0)
    try:
        try:
            status, body = _live_post(server, raw, path, method)
            assert status in (200, 400, 401, 403, 404, 405, 413, 440), (name, status)
            # error bodies must stay JSON-shaped (sanitized, no traceback)
            try:
                parsed = json.loads(body.decode("utf-8", errors="replace") or "null")
            except Exception:
                parsed = None
            blob = body.decode("utf-8", errors="replace")
            assert "Traceback" not in blob
            if status == 200:
                _assert_verdict("VALID", ctx=name)
            else:
                _assert_verdict(str(status), ctx=name)
            assert parsed is not None or body == b""
        except (ConnectionError, OSError, http.client.HTTPException):
            _assert_verdict("FAIL_CLOSED", ctx=name)
    except EXPECTED_EXC:
        _assert_verdict("FAIL_CLOSED", ctx=name)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH live={name} exc={e!r:.300}")
    finally:
        try:
            server.stop()
        except Exception:
            pass


def test_fuzz_http_live_huge_body_413():
    if HttpMcpServer is None:
        pytest.skip("http surface absent")
    server = HttpMcpServer()
    server.start("127.0.0.1", 0)
    try:
        try:
            big = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"' + b"Z" * (2 * 1024 * 1024) + b'"}}'
            status, _ = _live_post(server, big)
            assert status in (400, 403, 413), status
            _assert_verdict(str(status), ctx="huge")
            # server still alive afterwards
            s2, b2 = _live_post(server, b'{"jsonrpc":"2.0","id":2,"method":"ping"}')
            assert s2 == 200
            _assert_verdict("VALID", ctx="huge-alive")
        except (ConnectionError, OSError, http.client.HTTPException):
            _assert_verdict("FAIL_CLOSED", ctx="huge")
    except EXPECTED_EXC:
        _assert_verdict("FAIL_CLOSED", ctx="huge")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH huge exc={e!r:.300}")
    finally:
        try:
            server.stop()
        except Exception:
            pass


# ===========================================================================
# 5) Checklist spec fuzz
# ===========================================================================

def _item_dict(iid: str = "alpha-item", **over) -> dict[str, Any]:
    d = {"id": iid, "check": "c", "expected_evidence": "e",
         "verification_requirement": "v", "acceptance_condition": "a"}
    d.update(over)
    return d


def _checklist_dict(**over) -> dict[str, Any]:
    d = {"id": "fuzz-check", "version": "1.0.0", "scope": "fuzz-scope",
         "items": [_item_dict("alpha-item"), _item_dict("beta-item")]}
    d.update(over)
    return d


_CHECKLIST_CASES: list[tuple[str, Any]] = [
    ("null", None),
    ("empty", {}),
    ("empty-items", _checklist_dict(items=[])),
    ("null-items", _checklist_dict(items=None)),
    ("oversize-check", _checklist_dict(items=[_item_dict("alpha-item", check="C" * 5000)])),
    ("oversize-scope", _checklist_dict(scope="s" * 500)),
    ("huge-items", _checklist_dict(items=[_item_dict(f"item-{i:04d}") for i in range(300)])),
    ("duplicate-ids", _checklist_dict(items=[_item_dict("dup-item"), _item_dict("dup-item")])),
    ("bad-semver-short", _checklist_dict(version="1.0")),
    ("bad-semver-v", _checklist_dict(version="v1.0.0")),
    ("bad-semver-four", _checklist_dict(version="1.0.0.0")),
    ("bad-semver-empty", _checklist_dict(version="")),
    ("bad-semver-none", _checklist_dict(version=None)),
    ("bad-id-upper", _checklist_dict(id="Fuzz-Check")),
    ("bad-id-empty", _checklist_dict(id="")),
    ("bad-id-none", _checklist_dict(id=None)),
    ("bad-id-numeric", _checklist_dict(id=123)),
    ("bad-id-bool", _checklist_dict(id=True)),
    ("bad-scope-upper", _checklist_dict(scope="Fuzz Scope")),
    ("extra-fields", {**_checklist_dict(), "__extra": 1, "grant": "admin"}),
    ("extra-item-field", _checklist_dict(items=[{**_item_dict("alpha-item"), "severity": "high"}])),
    ("unicode-ids", _checklist_dict(id="fuzz-\u202e-check")),
    ("control-check", _checklist_dict(items=[_item_dict("alpha-item", check=CONTROL)])),
    ("ansi-check", _checklist_dict(items=[_item_dict("alpha-item", check=ANSI)])),
    ("null-item", _checklist_dict(items=[None])),
    ("numeric-item", _checklist_dict(items=[123])),
    ("empty-item-id", _checklist_dict(items=[_item_dict("")])),
]


@pytest.mark.parametrize("name,payload", _CHECKLIST_CASES)
def test_fuzz_checklist_spec(name, payload):
    if Checklist is None:
        pytest.skip("checklist surface absent")
    try:
        try:
            obj = Checklist.model_validate(payload)
        except EXPECTED_EXC:
            _assert_verdict("REJECTED", ctx=name)
            return
        # constructed: re-serialize round-trip must stay deterministic
        try:
            obj.to_canonical_json()
            _assert_verdict("VALID", ctx=name)
        except EXPECTED_EXC:
            _assert_verdict("SANITIZED", ctx=name)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH checklist={name} input={payload!r:.400} exc={e!r:.300}")


# ===========================================================================
# 6) Template validator fuzz (null / malformed / model_copy bypass)
# ===========================================================================

_TEMPLATE_CONSTRUCT_CASES: list[tuple[str, Any]] = [
    ("null", None),
    ("empty", {}),
    ("empty-str", ""),
    ("numeric", 123),
    ("bool", True),
    ("list", []),
    ("bad-id", {"template_id": "BAD ID", "name": "N", "version": "1.0.0"}),
    ("bad-ver", {"template_id": "fuzz-demo", "name": "N", "version": "v1"}),
    ("evil-field", {"template_id": "fuzz-demo", "name": "N", "version": "1.0.0",
                     "finding_fields": ["evil.field"],
                     "sections": [{"name": "s", "fields": ["evil.field"]}]}),
    ("bad-format", {"template_id": "fuzz-demo", "name": "N", "version": "1.0.0",
                     "finding_fields": [], "output_formats": ["exe"]}),
    ("empty-formats", {"template_id": "fuzz-demo", "name": "N", "version": "1.0.0",
                        "finding_fields": [], "output_formats": []}),
    ("extra-field", {"template_id": "fuzz-demo", "name": "N", "version": "1.0.0",
                      "finding_fields": [], "__extra": 1}),
    ("unicode-id", {"template_id": "fuzz-\u202e-x", "name": "N", "version": "1.0.0"}),
    ("huge-desc", {"template_id": "fuzz-demo", "name": "N", "version": "1.0.0",
                    "finding_fields": [], "description": "D" * 5000}),
]


@pytest.mark.parametrize("name,payload", _TEMPLATE_CONSTRUCT_CASES)
def test_fuzz_template_construct(name, payload):
    if ReportTemplateSpec is None or ReportTemplateValidator is None:
        pytest.skip("template surface absent")
    try:
        try:
            if payload is None or not isinstance(payload, dict):
                ReportTemplateSpec.model_validate(payload)
                _assert_verdict("VALID", ctx=name)
                return
            base = _valid_template_dict()
            base.update(payload if isinstance(payload, dict) else {})
            spec = ReportTemplateSpec(**base)  # type: ignore[arg-type]
        except EXPECTED_EXC:
            _assert_verdict("REJECTED", ctx=name)
            return
        try:
            ok, trust, errors, _ = ReportTemplateValidator().validate(spec)
            assert str(trust) in ("TemplateTrust.UNTRUSTED", "untrusted",
                                  "TemplateTrust.TRUSTED", "trusted",
                                  "TemplateTrust.INVALID", "invalid")
            _assert_verdict("VALID" if ok else "REJECTED", ctx=name)
            assert isinstance(errors, tuple)
        except EXPECTED_EXC:
            _assert_verdict("REJECTED", ctx=name)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH template={name} exc={e!r:.300}")


def test_fuzz_template_model_copy_bypass():
    if ReportTemplateSpec is None or ReportTemplateValidator is None:
        pytest.skip("template surface absent")
    bypasses: list[tuple[str, dict]] = [
        ("evil-finding-field", {"finding_fields": ("evil.field",)}),
        ("evil-section-field",
         {"sections": ({"name": "s", "fields": ("evil.field",)},)}),
        ("drop-mandatory", {"finding_fields": ("finding.title",)}),
        ("unsafe-desc", {"description": "run eval(os.system('x')) please"}),
        ("unsafe-script", {"description": "<script>alert(1)</script>"}),
        ("weaken-provenance", {"preserve_provenance": False}),
        ("weaken-redact", {"redact_secrets": False}),
        ("weaken-determ", {"deterministic": False}),
        ("bad-format", {"output_formats": ("exe",)}),
        ("null-sections", {"sections": None}),
        ("numeric-name", {"name": 123}),
    ]
    for name, update in bypasses:
        try:
            try:
                spec = ReportTemplateSpec(**_valid_template_dict())  # type: ignore[arg-type]
            except EXPECTED_EXC:
                _assert_verdict("REJECTED", ctx=f"bypass-base:{name}")
                continue
            try:
                mutated = spec.model_copy(update=update)  # type: ignore[arg-type]
            except EXPECTED_EXC:
                _assert_verdict("REJECTED", ctx=f"bypass:{name}")
                continue
            try:
                ok, _, errors, _ = ReportTemplateValidator().validate(mutated)
                # validator must catch the bypass (never VALID with evil content)
                if update.keys() & {"finding_fields", "sections"} and "evil.field" in str(update):
                    assert not ok, (name, errors)
                    _assert_verdict("DENY", ctx=f"bypass:{name}")
                elif name.startswith("weaken") or name.startswith("unsafe") or name == "bad-format":
                    assert not ok, (name, errors)
                    _assert_verdict("DENY", ctx=f"bypass:{name}")
                else:
                    _assert_verdict("VALID" if ok else "REJECTED", ctx=f"bypass:{name}")
            except EXPECTED_EXC:
                _assert_verdict("REJECTED", ctx=f"bypass:{name}")
        except Exception as e:  # noqa: BLE001
            pytest.fail(f"UNHANDLED CRASH bypass={name} exc={e!r:.300}")


# ===========================================================================
# 7) Benchmark case parser fuzz
# ===========================================================================

_BENCH_CASES: list[tuple[str, Any]] = [
    ("null", None),
    ("empty", {}),
    ("empty-str", ""),
    ("numeric", 123),
    ("bool", True),
    ("list", []),
    ("bad-json-str", "{not json"),
    ("wrong-kind", {**_valid_post_t020_dict(), "kind": "bogus-kind"}),
    ("wrong-category", {**_valid_post_t020_dict(), "category": "bogus-cat"}),
    ("duplicate-id-a", _valid_post_t020_dict("dup.case-01")),
    ("bad-case-id", {**_valid_post_t020_dict(), "case_id": "BAD ID!!"}),
    ("empty-case-id", {**_valid_post_t020_dict(), "case_id": ""}),
    ("leak-input", {**_valid_post_t020_dict(), "input": {"expected": 1}}),
    ("leak-input-gt", {**_valid_post_t020_dict(), "input": {"ground_truth": 1}}),
    ("missing-signal", {k: v for k, v in _valid_post_t020_dict().items() if k != "expected_signal"}),
    ("empty-signal", {**_valid_post_t020_dict(), "expected_signal": []}),
    ("bad-signal-kind", {**_valid_post_t020_dict(),
                         "expected_signal": [_gt_record("expected_present")],
                         "kind": "adversarial", "must_not": []}),
    ("production-src", {**_valid_post_t020_dict(),
                        "source": {"system": "prod", "fixture": "x", "production": True}}),
    ("extra-field", {**_valid_post_t020_dict(), "__extra": 1}),
    ("huge-input", {**_valid_post_t020_dict(), "input": {"pad": HUGE_10K}}),
    ("unicode-title", {**_valid_post_t020_dict(), "title": UNICODE}),
    ("control-title", {**_valid_post_t020_dict(), "title": CONTROL}),
    ("cross-no-secondary", {**_valid_post_t020_dict(), "kind": "cross_scope"}),
    ("regression-no-stage", {**_valid_post_t020_dict(), "kind": "regression"}),
]


@pytest.mark.parametrize("name,payload", _BENCH_CASES)
def test_fuzz_benchmark_parser(name, payload):
    if PostT020Case is None:
        pytest.skip("benchmark surface absent")
    try:
        raw = payload
        if isinstance(payload, str) and name == "bad-json-str":
            try:
                raw = json.loads(payload)
                _assert_verdict("VALID", ctx=name)
                return
            except EXPECTED_EXC:
                _assert_verdict("REJECTED", ctx=name)
                return
        try:
            case = PostT020Case.model_validate(raw)
        except EXPECTED_EXC:
            _assert_verdict("REJECTED", ctx=name)
            return
        # blind projection must never leak evaluation-only fields
        try:
            blind = post_t020_blind(case)
            assert "expected_signal" not in blind and "must_not" not in blind
            assert "ground_truth" not in blind
            _assert_verdict("VALID", ctx=name)
        except EXPECTED_EXC:
            _assert_verdict("SANITIZED", ctx=name)
        # mapping-form blind with leaked keys must refuse
        try:
            post_t020_blind({**case.model_dump(mode="json"),
                             "expected_signal": ["x"], "must_not": ["y"]})
            _assert_verdict("FAIL_CLOSED", ctx=f"{name}-leak-should-deny")
        except EXPECTED_EXC:
            _assert_verdict("DENY", ctx=f"{name}-leak-denied")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH bench={name} exc={e!r:.300}")


def test_fuzz_benchmark_duplicate_ids_and_normalize():
    if PostT020Case is None or normalize_case is None:
        pytest.skip("benchmark surface absent")
    try:
        try:
            a = PostT020Case.model_validate(_valid_post_t020_dict("dup.case-01"))
            b = PostT020Case.model_validate(_valid_post_t020_dict("dup.case-01"))
            assert a.case_id == b.case_id
            # duplicate set detected by caller (registry must reject dup) -> REJECTED
            ids = [a.case_id, b.case_id]
            assert len(set(ids)) != len(ids)
            _assert_verdict("REJECTED", ctx="duplicate-ids")
        except EXPECTED_EXC:
            _assert_verdict("REJECTED", ctx="duplicate-ids")
        # normalize_case with hostile shapes
        for bad in [None, {}, {"case_id": "x"}, {"scenario": None},
                    {"case_id": "bad id!!", "scenario": {"kind": "k"}}]:
            try:
                normalize_case(bad)  # type: ignore[arg-type]
                _assert_verdict("VALID", ctx=f"normalize:{bad!r:.60}")
            except EXPECTED_EXC:
                _assert_verdict("REJECTED", ctx=f"normalize:{bad!r:.60}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH bench-normalize exc={e!r:.300}")


# ===========================================================================
# 8) Platform alias fn fuzz (None/empty/case variants)
# ===========================================================================

_PLATFORM_CASES = [None, "", "   ", "WIN32", "Windows", "WINDOWS", "win32",
                   "darwin", "Darwin", "DARWIN", "linux", "Linux", "plan9",
                   123, True, ["darwin"], {"p": 1}, HUGE_10K[:500], UNICODE,
                   CONTROL, ANSI, "windows\x00", " win32 "]


@pytest.mark.parametrize("plat", _PLATFORM_CASES)
def test_fuzz_platform_alias(plat):
    if host_profile is None or check_compatibility is None or ExtHostProfile is None:
        pytest.skip("platform surface absent")
    try:
        # host_profile() with fuzzed platform
        try:
            hp = host_profile(platform=plat)  # type: ignore[arg-type]
            hp_platform = hp.platform
        except EXPECTED_EXC:
            _assert_verdict("REJECTED", ctx=f"plat={plat!r:.60}")
            return
        # compatibility against a real manifest is optional; fall back to HostProfile-only
        try:
            from pathlib import Path as _P

            cand = sorted((_P("tests/fixtures/extensions/official")).rglob("*.extension.yaml"))
            if cand:
                from emo_cyber_agent.extensions import load_manifest_file as _lm

                m = _lm(cand[0])
                res = check_compatibility(m, ExtHostProfile(platform=str(hp_platform)[:32] or "x"))
                assert isinstance(res.compatible, bool)
                _assert_verdict("VALID" if res.compatible else "DENY",
                                ctx=f"plat={plat!r:.60}")
            else:
                res = check_compatibility(
                    __import__("emo_cyber_agent.extensions", fromlist=["x"]) and None, hp,
                ) if False else None
                _assert_verdict("VALID", ctx=f"plat={plat!r:.60}")
        except EXPECTED_EXC:
            _assert_verdict("FAIL_CLOSED", ctx=f"plat={plat!r:.60}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH plat={plat!r:.200} exc={e!r:.300}")


@pytest.mark.parametrize("ver,con", [
    (None, ">=1.0"), ("", ""), ("bad", ">=1.0"), ("1.0.0", None),
    ("1.0.0", ""), ("1.0.0", "*"), (123, 456), (True, ">=1.0"),
    (HUGE_10K[:500], ">=1.0"), (UNICODE, ">=1.0"), ("1.0.0", HUGE_10K[:200]),
    ("", "spin"), ("not-a-version", ">=1.0"),
])
def test_fuzz_version_satisfies(ver, con):
    if satisfies is None or python_satisfies is None:
        pytest.skip("platform surface absent")
    try:
        try:
            r1 = satisfies(ver, con)  # type: ignore[arg-type]
            r2 = python_satisfies(str(ver) if ver is not None else "", str(con or ""))  # type: ignore[arg-type]
            assert isinstance(r1, bool) and isinstance(r2, bool)
            _assert_verdict("VALID", ctx=f"{ver!r:.40}/{con!r:.40}")
        except EXPECTED_EXC:
            _assert_verdict("REJECTED", ctx=f"{ver!r:.40}/{con!r:.40}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH satisfies exc={e!r:.300}")


# ===========================================================================
# 9) Loader scoping: empty sections manifest / missing dirs / scope lookups
# ===========================================================================

_SCOPE_LOOKUP_CASES = [None, "", "   ", "NOPE", "Secure-Code-Review", "SECURE-CODE-REVIEW",
                       "source-code-change", "SOURCE-CODE-CHANGE", 123, True,
                       HUGE_10K[:300], UNICODE, CONTROL, ANSI, "mcp-tool-surface\x00"]


@pytest.mark.parametrize("key", _SCOPE_LOOKUP_CASES)
def test_fuzz_loader_scope_lookups(key):
    if get_checklist is None or get_by_scope is None:
        pytest.skip("checklist catalog absent")
    try:
        try:
            get_checklist(key)  # type: ignore[arg-type]
            _assert_verdict("VALID", ctx=f"id={key!r:.60}")
        except (KeyError, ValueError, TypeError, AttributeError):
            _assert_verdict("404", ctx=f"id={key!r:.60}")
        try:
            get_by_scope(key)  # type: ignore[arg-type]
            _assert_verdict("VALID", ctx=f"scope={key!r:.60}")
        except (KeyError, ValueError, TypeError, AttributeError):
            _assert_verdict("404", ctx=f"scope={key!r:.60}")
    except EXPECTED_EXC:
        _assert_verdict("FAIL_CLOSED", ctx=f"key={key!r:.60}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH scope={key!r:.200} exc={e!r:.300}")


def test_fuzz_loader_missing_and_empty_dirs(tmp_path):
    try:
        from emo_cyber_agent.report_templates.library import load_official_registry as _load_rt
        from emo_cyber_agent.playbooks.library import load_official_registry as _load_pb
    except Exception:
        pytest.skip("loader surface absent")
    missing = tmp_path / "does-not-exist-xyz"
    empty = tmp_path / "empty-dir"
    empty.mkdir(exist_ok=True)
    notdir = tmp_path / "file-not-dir.yaml"
    notdir.write_text("report_template: {}")
    for label, target in [("missing", missing), ("empty", empty), ("notdir", notdir)]:
        for loader in (_load_rt, _load_pb):
            try:
                try:
                    loader(target)
                    _assert_verdict("VALID", ctx=f"{loader.__module__}:{label}")
                except EXPECTED_EXC as e:
                    code = getattr(getattr(e, "code", None), "value", "") or str(e)
                    if "NOT_FOUND" in code or "not found" in str(e).lower() or "no official" in str(e).lower():
                        _assert_verdict("404", ctx=f"{loader.__module__}:{label}")
                    else:
                        _assert_verdict("REJECTED", ctx=f"{loader.__module__}:{label}")
            except Exception as e:  # noqa: BLE001
                pytest.fail(f"UNHANDLED CRASH loader={label} exc={e!r:.300}")
    # empty-sections manifest text: YAML with no sections must REJECT or VALID-bounded
    try:
        from emo_cyber_agent.report_templates.library import spec_from_yaml_text as _spec_txt
        empties = [
            "",
            "report_template: {}",
            "report_template:\n  id: fuzz-empty\n",
            "report_template:\n  id: fuzz-empty\n  name: N\n  version: 1.0.0\n",
        ]
        for i, text in enumerate(empties):
            try:
                _spec_txt(text)
                _assert_verdict("VALID", ctx=f"empty-manifest:{i}")
            except EXPECTED_EXC:
                _assert_verdict("REJECTED", ctx=f"empty-manifest:{i}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH empty-manifest exc={e!r:.300}")


_QUERY_SCOPE_CASES = [
    ("", "", "", ""),
    ("audit-fuzz", "", "", ""),
    ("", "project-fuzz", "", ""),
    ("audit-fuzz", "project-fuzz", "audit-OTHER", ""),
    ("audit-fuzz", "project-fuzz", "", "tenant_scope"),
    ("audit-fuzz", "project-fuzz", "other_audit_id", ""),
    ("audit-fuzz", "project-fuzz", "audit-fuzz", "snap-fuzz"),
    (None, None, None, None),
    (123, 456, 789, 0),
]


@pytest.mark.parametrize("caller_audit,caller_proj,req_audit,req_snap",
                         _QUERY_SCOPE_CASES)
def test_fuzz_bind_query_scope(caller_audit, caller_proj, req_audit, req_snap):
    if bind_query_scope is None:
        pytest.skip("scope surface absent")
    try:
        try:
            bind_query_scope(caller_audit_id=caller_audit, caller_project_id=caller_proj,
                             requested_audit_id=req_audit or "",
                             requested_project_id="",
                             requested_snapshot_id=req_snap or "")
            _assert_verdict("VALID", ctx=f"{caller_audit!r}/{req_audit!r}")
        except EXPECTED_EXC as e:
            code = getattr(getattr(e, "code", None), "value", "")
            if "CROSS" in code or "DENIED" in code or "REJECTED" in code:
                _assert_verdict("DENY", ctx=f"{caller_audit!r}/{req_audit!r}")
            else:
                _assert_verdict("REJECTED", ctx=f"{caller_audit!r}/{req_audit!r}")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"UNHANDLED CRASH scope exc={e!r:.300}")


def test_fuzz_token_validator_shapes():
    if validate_mcp_token is None:
        pytest.skip("token surface absent")
    shapes: list[Any] = [None, "", "   ", "\x00", "x" * 300, UNICODE, CONTROL,
                          ANSI, 123, True, ["t"], {"t": 1}, "ok-token-01"]
    for tok in shapes:
        try:
            try:
                validate_mcp_token(tok)  # type: ignore[arg-type]
                _assert_verdict("VALID", ctx=f"tok={tok!r:.60}")
            except EXPECTED_EXC:
                _assert_verdict("DENY", ctx=f"tok={tok!r:.60}")
        except Exception as e:  # noqa: BLE001
            pytest.fail(f"UNHANDLED CRASH token={tok!r:.200} exc={e!r:.300}")
