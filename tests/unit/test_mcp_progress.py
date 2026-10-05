"""MCP <-> progress binding tests (Sub-Agent 3 scope).

Proves the reporting-only progress wiring in mcp/server.py:
token present -> ordered notifications; token absent -> silence;
terminal COMPLETED/FAILED; malformed progress payload never breaks
execution; JSON-RPC framing stays valid.
"""

import io
import json

import pytest

from emo_cyber_agent.mcp import protocol as proto
from emo_cyber_agent.mcp.server import create_server

_STATUS_ARGS = {}
_TOKEN = "tok-abc-123"


def _call(server, name, arguments, req_id=1, meta=None):
    params = {"name": name, "arguments": arguments}
    if meta is not None:
        params["_meta"] = meta
    response = server.handle_message(
        {"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params}
    )
    assert response is not None  # requests carrying an id always get a response
    return response


def test_token_present_emits_ordered_notifications():
    server = create_server()
    response = _call(server, "cyber_status", dict(_STATUS_ARGS), meta={"progressToken": _TOKEN})
    assert response["result"], response
    notes = server.drain_notifications()
    assert [n["method"] for n in notes] == ["notifications/progress"] * 4
    phases = [n["params"]["phase"] for n in notes]
    assert phases == ["STARTED", "RUNNING", "FINALIZING", "COMPLETED"]
    for note in notes:
        assert note["jsonrpc"] == "2.0"
        assert "id" not in note  # notifications carry no id
        assert note["params"]["progressToken"] == _TOKEN
        assert set(note["params"]) == {"progressToken", "phase", "percent", "message_code"}
    percents = [n["params"]["percent"] for n in notes]
    assert percents == sorted(percents) and len(set(percents)) == 4  # traceable monotone sequence
    assert [n["params"]["message_code"] for n in notes] == [
        "RUN_STARTED",
        "PHASE_STARTED",
        "PHASE_STARTED",
        "OPERATION_COMPLETE",
    ]
    json.dumps(notes)  # wire-serializable


def test_token_absent_zero_notifications():
    server = create_server()
    response = _call(server, "cyber_status", dict(_STATUS_ARGS))
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["status"] == "ok"
    assert server.drain_notifications() == []


def test_int_token_echoed_back():
    server = create_server()
    _call(server, "cyber_status", dict(_STATUS_ARGS), meta={"progressToken": 7})
    notes = server.drain_notifications()
    assert len(notes) == 4
    assert all(n["params"]["progressToken"] == 7 for n in notes)


def test_completion_terminal_notification():
    server = create_server()
    _call(server, "cyber_status", dict(_STATUS_ARGS), meta={"progressToken": _TOKEN})
    terminal = server.drain_notifications()[-1]
    assert terminal["params"]["phase"] == "COMPLETED"
    assert terminal["params"]["percent"] == 100.0
    assert terminal["params"]["message_code"] == "OPERATION_COMPLETE"


def test_domain_error_terminal_failed_but_response_valid():
    from emo_cyber_agent.core.correlation import FindingCandidate

    server = create_server()
    candidate = FindingCandidate(audit_id="B", hypothesis="h", evidence_ids=("e1",)).model_dump(mode="json")
    response = _call(
        server,
        "cyber_verify",
        {
            "audit_id": "A",
            "candidate": candidate,
            "method": "static_confirmation",
            "target": {"kind": "file", "locator": "src/a.py"},
            "rationale": "x",
        },
        meta={"progressToken": _TOKEN},
    )
    # Domain denial rides inside a valid result envelope (isError), not a JSON-RPC error.
    assert response["jsonrpc"] == "2.0" and response["id"] == 1 and "result" in response
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["status"] == "error" and payload["code"] == proto.DOMAIN_PERMISSION_DENIED
    notes = server.drain_notifications()
    assert [n["params"]["phase"] for n in notes] == ["STARTED", "RUNNING", "FINALIZING", "FAILED"]
    assert notes[-1]["params"]["message_code"] == "OPERATION_FAILED"


def test_exception_path_terminal_failed_no_crash():
    server = create_server()
    response = _call(server, "cyber_audit", {}, meta={"progressToken": _TOKEN})
    assert response["error"]["code"] == proto.INVALID_PARAMS  # still a valid error envelope
    assert response["jsonrpc"] == "2.0" and response["id"] == 1
    notes = server.drain_notifications()
    assert [n["params"]["phase"] for n in notes] == ["STARTED", "RUNNING", "FAILED"]
    assert notes[-1]["params"]["message_code"] == "OPERATION_FAILED"


@pytest.mark.parametrize(
    "meta",
    [
        {"progressToken": True},  # bool is not a valid token
        {"progressToken": False},
        {"progressToken": -3},  # negative int rejected
        {"progressToken": ""},  # empty string rejected
        {"progressToken": "   "},
        {"progressToken": "x" * 257},  # over length cap
        {"progressToken": {"nested": "object"}},  # wrong type
        {"progressToken": ["list"]},
        {"progressToken": None},
        {},  # token key missing
        "not-a-dict",  # _meta wrong type entirely
        ["also", "wrong"],
    ],
)
def test_malformed_progress_payload_runs_normally(meta):
    server = create_server()
    response = _call(server, "cyber_status", dict(_STATUS_ARGS), meta=meta)
    assert "result" in response, (meta, response)
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["status"] == "ok"
    assert server.drain_notifications() == []  # no token -> silence, no failure


def test_jsonrpc_response_valid_with_token():
    server = create_server()
    response = _call(server, "cyber_status", dict(_STATUS_ARGS), req_id=42, meta={"progressToken": _TOKEN})
    assert response == {
        "jsonrpc": "2.0",
        "id": 42,
        "result": response["result"],
    }
    text = response["result"]["content"][0]["text"]
    assert json.loads(text)["status"] == "ok"  # payload intact alongside notifications
    json.dumps(response)  # envelope itself serializes


def test_notifications_carry_no_secrets_or_tool_io():
    server = create_server()
    secret_target = "ghp_FAKE999secret-target-value"
    response = _call(server, "cyber_audit", {"target": secret_target}, meta={"progressToken": _TOKEN})
    assert "result" in response, response
    notes = server.drain_notifications()
    blob = json.dumps(notes)
    assert secret_target not in blob
    lowered = blob.lower()
    for leaked in ("ghp_", "credential", "secret", "password", "prompt", "finding"):
        assert leaked not in lowered
    assert len(notes) == 4 and notes[-1]["params"]["phase"] == "COMPLETED"


def test_result_identical_with_and_without_token():
    # Reporting-only: the token must not change dispatch outcome or authority.
    with_token = _call(create_server(), "cyber_status", dict(_STATUS_ARGS), meta={"progressToken": _TOKEN})
    without_token = _call(create_server(), "cyber_status", dict(_STATUS_ARGS))
    assert with_token["result"] == without_token["result"]


def test_stdio_interleaves_notifications_before_response():
    server = create_server()
    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "cyber_status", "arguments": {}, "_meta": {"progressToken": _TOKEN}},
        }
    )
    stdout = io.StringIO()
    assert server.run_stdio(stdin=io.StringIO(request + "\n"), stdout=stdout) == 0
    lines = [json.loads(line) for line in stdout.getvalue().strip().split("\n")]
    assert len(lines) == 5  # 4 notifications + 1 response
    assert all(line.get("method") == "notifications/progress" and "id" not in line for line in lines[:4])
    assert lines[4] == {"jsonrpc": "2.0", "id": 9, "result": lines[4]["result"]}
    assert json.loads(lines[4]["result"]["content"][0]["text"])["status"] == "ok"
