"""ECA CLI <-> progress binding tests (offline).

Proves the CLI execution paths (audit/review) are wired to
ProgressState + ProgressReporter without breaking output contracts:

- CLI execution emits ProgressEvent(s) with terminal COMPLETED.
- Human mode shows concise progress lines on stderr, business payload on stdout.
- JSON mode: stdout parses as pure JSON payload with no progress keys;
  progress never leaks to stdout.
- Failure path emits a FAILED terminal event; stdout stays clean.
- Cancellation (KeyboardInterrupt) emits CANCELLED, exit 130, and never a
  misleading COMPLETED.
"""

import json

from typer.testing import CliRunner

from emo_cyber_agent.cli.main import EXIT_INVALID_INPUT, EXIT_INTERRUPTED, app
from emo_cyber_agent.progress.events import ProgressEvent, ProgressEventType
from emo_cyber_agent.progress.reporter import ProgressReporter

runner = CliRunner()

_ALLOWED_PHASES = {"STARTED", "RUNNING", "FINALIZING", "COMPLETED", "FAILED", "CANCELLED"}
_ALLOWED_CODES = {"RUN_STARTED", "PHASE_STARTED", "OPERATION_COMPLETE", "OPERATION_FAILED", "OPERATION_CANCELLED"}
_EXPECTED_EVENT_KEYS = {
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


def _collect_events(monkeypatch) -> list:
    """Spy on ProgressReporter.report; return the live event list."""
    collected: list = []
    original = ProgressReporter.report

    def _spy(self, event):
        collected.append(event)
        return original(self, event)

    monkeypatch.setattr(ProgressReporter, "report", _spy)
    return collected


def _assert_fixed_vocabulary(events) -> None:
    assert events, "expected at least one ProgressEvent"
    for event in events:
        assert isinstance(event, ProgressEvent)
        assert event.phase in _ALLOWED_PHASES, event.phase
        assert event.message_code in _ALLOWED_CODES, event.message_code
        assert set(event.to_dict().keys()) == _EXPECTED_EVENT_KEYS  # fixed schema, no leak fields


def test_audit_emits_progress_events_with_completed_terminal(monkeypatch):
    events = _collect_events(monkeypatch)
    out = runner.invoke(app, ["audit", "."])
    assert out.exit_code == 0, out.output
    _assert_fixed_vocabulary(events)
    terminal = events[-1]
    assert (terminal.phase, terminal.status) == ("COMPLETED", "COMPLETED")
    assert terminal.message_code == "OPERATION_COMPLETE"
    assert terminal.percent == 100.0


def test_human_output_shows_progress_on_stderr_only():
    out = runner.invoke(app, ["audit", "."])
    assert out.exit_code == 0, out.output
    assert "[audit] STARTED (RUN_STARTED)" in out.stderr
    assert "[audit] COMPLETED (OPERATION_COMPLETE)" in out.stderr
    assert "audit_id" in out.stdout
    assert "[audit]" not in out.stdout  # progress never pollutes business payload


def test_json_stdout_isolation():
    out = runner.invoke(app, ["audit", ".", "--format", "json"])
    assert out.exit_code == 0, out.output
    body = json.loads(out.stdout)  # strict: stdout must be pure JSON
    assert body["status"] == "ok" and "result" in body
    for key in ("phase", "phase_index", "message_code", "run_id", "percent", "OPERATION_COMPLETE", "COMPLETED"):
        assert key not in out.stdout, f"progress leak in JSON stdout: {key}"
    # JSON mode keeps stderr free of progress content. (Exact-empty check avoided:
    # interpreter RuntimeWarnings from unrelated GC timing can land on captured
    # stderr in combined runs; stdout purity above is the strict property.)
    for key in ("STARTED", "RUNNING", "FINALIZING", "COMPLETED", "OPERATION_COMPLETE", "RUN_STARTED", "[audit]"):
        assert key not in out.stderr, f"progress leak in JSON stderr: {key}"


def test_failure_path_emits_failed_and_keeps_stdout_clean(monkeypatch):
    events = _collect_events(monkeypatch)
    out = runner.invoke(app, ["audit", ".", "--mode", "bogus"])
    assert out.exit_code == EXIT_INVALID_INPUT
    _assert_fixed_vocabulary(events)
    terminal = events[-1]
    assert (terminal.phase, terminal.status) == ("FAILED", "FAILED")
    assert terminal.message_code == "OPERATION_FAILED"
    assert terminal.event_type == ProgressEventType.ERROR
    assert out.stdout == ""  # errors must not corrupt stdout
    assert out.stderr != ""  # diagnostics (incl. FAILED line) go to stderr


def test_cancellation_emits_cancelled_without_misleading_state(monkeypatch):
    import asyncio

    events = _collect_events(monkeypatch)

    def _boom(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(asyncio, "run", _boom)
    out = runner.invoke(app, ["audit", "."])
    assert out.exit_code == EXIT_INTERRUPTED
    _assert_fixed_vocabulary(events)
    terminal = events[-1]
    assert (terminal.phase, terminal.status) == ("CANCELLED", "CANCELLED")
    assert terminal.message_code == "OPERATION_CANCELLED"
    assert all(e.phase != "COMPLETED" for e in events)  # no misleading success state
    assert "audit_id" not in out.stdout  # no business payload on cancel


def test_review_emits_progress_with_completed_terminal(monkeypatch):
    events = _collect_events(monkeypatch)
    out = runner.invoke(app, ["review", "src/app.py"])
    assert out.exit_code == 0, out.output
    _assert_fixed_vocabulary(events)
    assert events[-1].phase == "COMPLETED"
    assert "[review] COMPLETED (OPERATION_COMPLETE)" in out.stderr


def test_review_failure_emits_failed(monkeypatch):
    events = _collect_events(monkeypatch)
    out = runner.invoke(app, ["review", "src/app.py", "--format", "yaml"])
    assert out.exit_code == EXIT_INVALID_INPUT
    assert events, "expected progress events even on invalid input"
    assert events[-1].phase == "FAILED"
    assert events[-1].event_type == ProgressEventType.ERROR
