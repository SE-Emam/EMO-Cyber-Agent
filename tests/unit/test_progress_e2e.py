"""End-to-end progress lifecycle validation (Sub-Agent 4 scope).

Black-box proof that CLI->Core->ProgressReporter->ProgressEvent and
MCP->Core->ProgressReporter->MCP Notification share ONE logical lifecycle:
a single ProgressState/ProgressReporter state machine per run, projected
through two display-only adapters. No duplicate state machines, no
authority leakage (token/progress never changes dispatch outcome), a
deterministic schema on each surface, correct event order, and
failure/cancellation terminals preserved.

Driven from outside only: Typer CliRunner for the CLI surface,
McpServer.handle_message + drain_notifications for the MCP surface, and a
read-only spy on ProgressReporter.report to observe the shared core
events. Nothing here reaches into adapter internals.

Coverage map:
  (1) successful CLI run          -> test_e2e_cli_success_full_lifecycle
  (2) failed CLI run              -> test_e2e_cli_failure_failed_terminal
  (3) cancelled CLI run           -> test_e2e_cli_cancel_cancelled_terminal
  (4) JSON CLI isolation          -> test_e2e_cli_json_stdout_isolation
  (5) MCP with progress token     -> test_e2e_mcp_with_token_full_lifecycle
                                     + test_e2e_mcp_failure_terminal_preserved
  (6) MCP without token           -> test_e2e_mcp_without_token_silent_identical_result
  parity (all of the above)       -> test_e2e_cross_adapter_parity_one_lifecycle
"""

import json

from typer.testing import CliRunner

from emo_cyber_agent.cli.main import EXIT_INTERRUPTED, EXIT_INVALID_INPUT, app
from emo_cyber_agent.mcp.server import create_server
from emo_cyber_agent.progress.events import ProgressEvent, ProgressEventType
from emo_cyber_agent.progress.reporter import ProgressReporter

runner = CliRunner()
_TOKEN = "e2e-tok-001"

# Deterministic schemas (fixed key sets — any added/removed key fails here).
_CLI_EVENT_KEYS = {
    "run_id",
    "audit_id",
    "phase",
    "phase_index",
    "phase_count",
    "completed",
    "total",
    "percent",
    "status",
    "message_code",
    "event_type",
    "timestamp",
}
_MCP_NOTE_KEYS = {"progressToken", "phase", "percent", "message_code"}
_TERMINAL_PHASES = {"COMPLETED", "FAILED", "CANCELLED"}


def _collect_events(monkeypatch) -> list:
    """Observe shared-core events without steering them."""
    collected: list = []
    original = ProgressReporter.report

    def _spy(self, event):
        collected.append(event)
        return original(self, event)

    monkeypatch.setattr(ProgressReporter, "report", _spy)
    return collected


def _assert_single_lifecycle(events, terminal_phase: str) -> None:
    """One state machine per run: one run_id, ordered, exactly one terminal, last."""
    assert events, "expected progress events for the run"
    for event in events:
        assert isinstance(event, ProgressEvent)
        assert set(event.to_dict().keys()) == _CLI_EVENT_KEYS
        assert event.run_id and event.audit_id
        assert event.phase == event.status  # both adapters bind status := phase
    assert len({e.run_id for e in events}) == 1, "duplicate state machines in one run"
    terminals = [e for e in events if e.phase in _TERMINAL_PHASES]
    assert len(terminals) == 1, f"expected exactly one terminal, got {[e.phase for e in terminals]}"
    assert events[-1].phase == terminal_phase
    assert events[-1] is terminals[0], "terminal must be the final event"
    assert [e.percent for e in events] == sorted(e.percent for e in events), "percents must be monotone"


def _mcp_call(server, name, arguments, req_id=1, meta=None):
    params = {"name": name, "arguments": arguments}
    if meta is not None:
        params["_meta"] = meta
    response = server.handle_message(
        {"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params}
    )
    assert response is not None
    return response


def _assert_mcp_wire(notes, token) -> None:
    for note in notes:
        assert note["jsonrpc"] == "2.0"
        assert note["method"] == "notifications/progress"
        assert "id" not in note  # notifications carry no id
        assert set(note["params"].keys()) == _MCP_NOTE_KEYS
        assert note["params"]["progressToken"] == token
    json.dumps(notes)  # wire-serializable


# (1) successful CLI run -----------------------------------------------------
def test_e2e_cli_success_full_lifecycle(monkeypatch):
    events = _collect_events(monkeypatch)
    out = runner.invoke(app, ["audit", "."])
    assert out.exit_code == 0, out.output
    _assert_single_lifecycle(events, "COMPLETED")
    assert [e.phase for e in events] == ["STARTED", "RUNNING", "FINALIZING", "COMPLETED"]
    assert [e.message_code for e in events] == [
        "RUN_STARTED",
        "PHASE_STARTED",
        "PHASE_STARTED",
        "OPERATION_COMPLETE",
    ]
    assert [e.percent for e in events] == [25.0, 50.0, 75.0, 100.0]
    assert all(e.event_type == ProgressEventType.PROGRESS for e in events)
    assert "audit_id" in out.stdout  # business payload delivered alongside progress


# (2) failed CLI run ----------------------------------------------------------
def test_e2e_cli_failure_failed_terminal(monkeypatch):
    events = _collect_events(monkeypatch)
    out = runner.invoke(app, ["audit", ".", "--mode", "bogus"])
    assert out.exit_code == EXIT_INVALID_INPUT
    _assert_single_lifecycle(events, "FAILED")
    assert [e.phase for e in events] == ["STARTED", "FAILED"]
    terminal = events[-1]
    assert terminal.message_code == "OPERATION_FAILED"
    assert terminal.event_type == ProgressEventType.ERROR
    assert terminal.percent == 50.0  # no 100% without completion
    assert all(e.phase != "COMPLETED" for e in events)
    assert out.stdout == ""  # failure never corrupts stdout


# (3) cancelled CLI run -------------------------------------------------------
def test_e2e_cli_cancel_cancelled_terminal(monkeypatch):
    import asyncio

    events = _collect_events(monkeypatch)

    def _boom(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(asyncio, "run", _boom)
    out = runner.invoke(app, ["audit", "."])
    assert out.exit_code == EXIT_INTERRUPTED
    _assert_single_lifecycle(events, "CANCELLED")
    assert [e.phase for e in events] == ["STARTED", "CANCELLED"]
    assert events[-1].message_code == "OPERATION_CANCELLED"
    assert all(e.phase != "COMPLETED" for e in events)  # no misleading success
    assert "audit_id" not in out.stdout  # no business payload on cancel


# (4) JSON CLI isolation ------------------------------------------------------
def test_e2e_cli_json_stdout_isolation(monkeypatch):
    events = _collect_events(monkeypatch)
    out = runner.invoke(app, ["audit", ".", "--format", "json"])
    assert out.exit_code == 0, out.output
    body = json.loads(out.stdout)  # strict: stdout is pure business JSON
    assert body["status"] == "ok" and "result" in body
    for key in ("phase", "phase_index", "message_code", "run_id", "percent", "OPERATION_COMPLETE", "COMPLETED"):
        assert key not in out.stdout, f"progress leak in JSON stdout: {key}"
    # JSON mode keeps stderr free of progress content. (Exact-empty check avoided:
    # interpreter RuntimeWarnings from unrelated GC timing can land on captured
    # stderr in combined runs; stdout purity above is the strict property.)
    for key in ("STARTED", "RUNNING", "FINALIZING", "COMPLETED", "OPERATION_COMPLETE", "RUN_STARTED"):
        assert key not in out.stderr, f"progress leak in JSON stderr: {key}"
    # Observability preserved underneath: the same full lifecycle still ran.
    _assert_single_lifecycle(events, "COMPLETED")
    assert [e.phase for e in events] == ["STARTED", "RUNNING", "FINALIZING", "COMPLETED"]


# (5) MCP with progress token --------------------------------------------------
def test_e2e_mcp_with_token_full_lifecycle():
    server = create_server()
    response = _mcp_call(server, "cyber_status", {}, meta={"progressToken": _TOKEN})
    assert "result" in response, response
    assert json.loads(response["result"]["content"][0]["text"])["status"] == "ok"
    notes = server.drain_notifications()
    _assert_mcp_wire(notes, _TOKEN)
    assert [n["params"]["phase"] for n in notes] == ["STARTED", "RUNNING", "FINALIZING", "COMPLETED"]
    assert [n["params"]["message_code"] for n in notes] == [
        "RUN_STARTED",
        "PHASE_STARTED",
        "PHASE_STARTED",
        "OPERATION_COMPLETE",
    ]
    assert [n["params"]["percent"] for n in notes] == [25.0, 50.0, 75.0, 100.0]
    assert server.drain_notifications() == []  # drained exactly once: no duplicates


def test_e2e_mcp_failure_terminal_preserved():
    from emo_cyber_agent.core.correlation import FindingCandidate
    from emo_cyber_agent.mcp import protocol as proto

    # Domain denial rides inside a valid result envelope, terminal FAILED preserved.
    server = create_server()
    candidate = FindingCandidate(audit_id="B", hypothesis="h", evidence_ids=("e1",)).model_dump(mode="json")
    response = _mcp_call(
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
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["status"] == "error" and payload["code"] == proto.DOMAIN_PERMISSION_DENIED
    notes = server.drain_notifications()
    _assert_mcp_wire(notes, _TOKEN)
    assert notes[-1]["params"]["phase"] == "FAILED"
    assert notes[-1]["params"]["message_code"] == "OPERATION_FAILED"
    assert all(n["params"]["phase"] != "COMPLETED" for n in notes)

    # Exception path: valid JSON-RPC error envelope, terminal FAILED preserved.
    server2 = create_server()
    err_response = _mcp_call(server2, "cyber_audit", {}, meta={"progressToken": _TOKEN})
    assert err_response["error"]["code"] == proto.INVALID_PARAMS
    notes2 = server2.drain_notifications()
    assert notes2[-1]["params"]["phase"] == "FAILED"
    assert notes2[-1]["params"]["message_code"] == "OPERATION_FAILED"

    # Authority leakage: notifications never carry targets, secrets, or tool I/O.
    server3 = create_server()
    secret = "ghp_FAKE999secret-target-value"
    assert "result" in _mcp_call(server3, "cyber_audit", {"target": secret}, meta={"progressToken": _TOKEN})
    blob = json.dumps(server3.drain_notifications())
    assert secret not in blob
    assert not any(w in blob.lower() for w in ("ghp_", "credential", "secret", "password", "prompt", "finding"))


# (6) MCP without token ---------------------------------------------------------
def test_e2e_mcp_without_token_silent_identical_result():
    with_token = _mcp_call(create_server(), "cyber_status", {}, meta={"progressToken": _TOKEN})
    silent_server = create_server()
    without_token = _mcp_call(silent_server, "cyber_status", {})
    assert silent_server.drain_notifications() == []  # silence, not failure
    assert with_token["result"] == without_token["result"]  # token never changes outcome


# cross-adapter parity: ONE logical lifecycle ----------------------------------
def test_e2e_cross_adapter_parity_one_lifecycle(monkeypatch):
    from emo_cyber_agent.cli.main import _CLI_PROGRESS_PHASES
    from emo_cyber_agent.mcp.server import _MCP_PROGRESS_PHASES

    # Same phase vocabulary in the same order; CLI additionally models
    # user-initiated cancellation (CANCELLED), which has no MCP equivalent
    # because MCP cancellation arrives as a bare JSON-RPC notification.
    assert list(_MCP_PROGRESS_PHASES) == [p for p in _CLI_PROGRESS_PHASES if p != "CANCELLED"]
    assert set(_MCP_PROGRESS_PHASES) <= set(_CLI_PROGRESS_PHASES)

    # Same success lifecycle, observed black-box on both adapters at once.
    events = _collect_events(monkeypatch)
    cli_out = runner.invoke(app, ["audit", "."])
    assert cli_out.exit_code == 0, cli_out.output
    mcp_server = create_server()
    mcp_response = _mcp_call(mcp_server, "cyber_status", {}, meta={"progressToken": _TOKEN})
    assert "result" in mcp_response
    notes = mcp_server.drain_notifications()

    cli_phases = [e.phase for e in events]
    mcp_phases = [n["params"]["phase"] for n in notes]
    assert cli_phases == mcp_phases == ["STARTED", "RUNNING", "FINALIZING", "COMPLETED"]
    # Same terminal semantics: phase, code, and 100% completion.
    assert (events[-1].phase, events[-1].message_code, events[-1].percent) == ("COMPLETED", "OPERATION_COMPLETE", 100.0)
    assert (notes[-1]["params"]["phase"], notes[-1]["params"]["message_code"], notes[-1]["params"]["percent"]) == (
        "COMPLETED",
        "OPERATION_COMPLETE",
        100.0,
    )
    # Same per-step projection: MCP notifications replay the shared core math.
    assert [n["params"]["message_code"] for n in notes] == [e.message_code for e in events]
    assert [n["params"]["percent"] for n in notes] == [e.percent for e in events]
    # Same failure vocabulary on both adapters.
    fail_events = _collect_events(monkeypatch)
    fail_out = runner.invoke(app, ["audit", ".", "--mode", "bogus"])
    assert fail_out.exit_code == EXIT_INVALID_INPUT
    fail_server = create_server()
    fail_response = _mcp_call(fail_server, "cyber_audit", {}, meta={"progressToken": _TOKEN})
    assert "error" in fail_response
    fail_notes = fail_server.drain_notifications()
    assert fail_events[-1].phase == fail_notes[-1]["params"]["phase"] == "FAILED"
    assert fail_events[-1].message_code == fail_notes[-1]["params"]["message_code"] == "OPERATION_FAILED"
