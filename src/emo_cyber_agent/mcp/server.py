"""MCP stdio adapter — ECA-T013.

High-level specialist tools only. No security logic: every tools/call is
framed here, validated for shape, delegated to Core, and serialized back.
State lives per request; the server object holds no audit state, so
concurrent audits cannot mix.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from emo_cyber_agent.mcp import protocol as _p
from emo_cyber_agent.mcp.delegate import dispatch, log_event
from emo_cyber_agent.mcp.tools import TOOL_NAMES, TOOLS, InvalidInput
from emo_cyber_agent.progress.events import ProgressEventType
from emo_cyber_agent.progress.reporter import ProgressReporter
from emo_cyber_agent.progress.state import ProgressState

# -- progress binding (reporting only) -------------------------------------
# Fixed lifecycle bracketing real execution transitions: request accepted
# (STARTED) -> Core executing (RUNNING) -> serializing (FINALIZING) ->
# terminal (COMPLETED | FAILED). Phase names and message codes are fixed
# constants; no arguments, targets, secrets, prompts, CoT, or tool outputs
# ever enter notifications. The progressToken is opaque and never reaches
# Core: it only binds notifications to the request. No capability is
# granted and no PolicyDecision changes; dispatch outcome is identical
# with or without a token.
_MCP_PROGRESS_PHASES = ("STARTED", "RUNNING", "FINALIZING", "COMPLETED", "FAILED")


def _extract_progress_token(params: Any) -> Any | None:
    """Read the opaque MCP progressToken. Any malformed value -> None
    (run normally, zero notifications, never fail the request)."""
    try:
        if not isinstance(params, dict):
            return None
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            return None
        token = meta.get("progressToken")
        if isinstance(token, bool):
            return None
        if isinstance(token, int):
            return token if token >= 0 else None
        if isinstance(token, str) and token.strip() and len(token) <= 256:
            return token
        return None
    except Exception:
        return None


class _McpProgressTracker:
    """Reporting-only tracker: advances a ProgressState and projects each
    event through reporter.mcp_notification into a minimal notification
    carrying progressToken/phase/percent/message_code only. Every method
    is failure-proof so reporting can never break tool execution."""

    def __init__(self, token: Any) -> None:
        import uuid

        self._token = token
        self._pending: list[dict[str, Any]] = []
        try:
            self._state = ProgressState(
                run_id=f"mcp-{uuid.uuid4().hex[:12]}",
                audit_id="mcp",
                phases=list(_MCP_PROGRESS_PHASES),
                total=4,
            )
            self._reporter = ProgressReporter()
        except Exception:
            self._state = None  # type: ignore[assignment]
            self._reporter = None  # type: ignore[assignment]

    def _emit(self, phase: str, message_code: str, event_type: ProgressEventType = ProgressEventType.PROGRESS) -> None:
        try:
            if self._state is None or self._reporter is None:
                return
            event = self._state.advance(phase=phase, status=phase, message_code=message_code, event_type=event_type)
            note = self._reporter.mcp_notification(event)
            raw = note.get("params", {}) if isinstance(note, dict) else {}
            if not isinstance(raw, dict):
                raw = {}
            self._pending.append(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {
                        "progressToken": self._token,
                        "phase": str(raw.get("phase", phase)),
                        "percent": raw.get("percent", 0.0),
                        "message_code": str(raw.get("message_code", message_code)),
                    },
                }
            )
        except Exception:
            pass  # reporting-only: never break execution

    def started(self) -> None:
        self._emit("STARTED", "RUN_STARTED")

    def running(self) -> None:
        self._emit("RUNNING", "PHASE_STARTED")

    def finalizing(self) -> None:
        self._emit("FINALIZING", "PHASE_STARTED")

    def completed(self) -> None:
        self._emit("COMPLETED", "OPERATION_COMPLETE")

    def failed(self) -> None:
        self._emit("FAILED", "OPERATION_FAILED", ProgressEventType.ERROR)

    def drain(self) -> list[dict[str, Any]]:
        pending = list(self._pending)
        del self._pending[:]
        return pending


class McpServer:
    """Stateless JSON-RPC dispatcher. No audit state is stored on self."""

    def __init__(self) -> None:
        self._initialized = False
        # Transport write queue only (no audit state): notifications queued
        # during handle_message are drained synchronously per message by
        # run_stdio (or by direct callers via drain_notifications), so
        # concurrent audits cannot mix.
        self._pending_notifications: list[dict[str, Any]] = []

    def drain_notifications(self) -> list[dict[str, Any]]:
        """Return and clear queued progress notifications (oldest first)."""
        pending = list(self._pending_notifications)
        del self._pending_notifications[:]
        return pending

    # -- protocol --
    def handle_message(self, message: Any) -> dict[str, Any] | None:
        if isinstance(message, list):
            return _p.error_envelope(None, _p.INVALID_REQUEST, "batch requests not supported")
        if not isinstance(message, dict):
            return _p.error_envelope(None, _p.INVALID_REQUEST, "message must be an object")
        if message.get("jsonrpc") != "2.0":
            return _p.error_envelope(message.get("id"), _p.INVALID_REQUEST, "jsonrpc must be 2.0")
        method = message.get("method")
        req_id = message.get("id")
        params = message.get("params", {})
        if not isinstance(method, str):
            return _p.error_envelope(req_id, _p.INVALID_REQUEST, "method must be a string")
        if req_id is None:
            self._notify(method, params)
            return None
        try:
            if method == "initialize":
                result = _p.initialize_result((params or {}).get("protocolVersion"))
                self._initialized = True
                return _p.result_envelope(req_id, result)
            if method == "ping":
                return _p.result_envelope(req_id, {})
            if method == "tools/list":
                return _p.result_envelope(req_id, {"tools": TOOLS})
            if method == "tools/call":
                return _p.result_envelope(req_id, self._call_tools(params))
            return _p.error_envelope(req_id, _p.METHOD_NOT_FOUND, f"unknown method: {method[:80]}")
        except _p.JsonRpcError as e:
            return _p.error_envelope(req_id, e.code, e.message, e.data)

    def _notify(self, method: str, params: Any) -> None:
        # Notifications carry no response by definition (initialized, cancelled, ...).
        return None

    def _call_tools(self, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict):
            raise _p.JsonRpcError(_p.INVALID_PARAMS, "tools/call params must be an object")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or name not in TOOL_NAMES:
            raise _p.JsonRpcError(_p.INVALID_PARAMS, f"unknown tool: {str(name)[:80]}")
        # Reporting-only binding: token presence adds notifications, never
        # alters validation, dispatch, or results. Malformed/absent -> None.
        token = _extract_progress_token(params)
        tracker = _McpProgressTracker(token) if token is not None else None
        try:
            if tracker is not None:
                tracker.started()
                tracker.running()
            try:
                payload = dispatch(name, arguments)
            except InvalidInput as e:
                raise _p.JsonRpcError(_p.INVALID_PARAMS, f"invalid arguments: {e}") from e
            if tracker is not None:
                tracker.finalizing()
            if isinstance(payload, dict) and payload.get("isError"):
                if tracker is not None:
                    tracker.failed()
                return payload
            if tracker is not None:
                tracker.completed()
            return {"content": [{"type": "text", "text": json.dumps(payload, sort_keys=True, ensure_ascii=False)}]}
        except Exception:
            if tracker is not None:
                try:
                    tracker.failed()
                except Exception:
                    pass
            raise
        finally:
            if tracker is not None:
                self._pending_notifications.extend(tracker.drain())

    # -- transport --
    def run_stdio(self, stdin: Any = None, stdout: Any = None) -> int:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        log_event(request_id="startup", audit_id="", tool="server", duration_ms=0, status="started")
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = _p.parse_line(line.rstrip("\n"))
            except _p.JsonRpcError as e:
                stdout.write(json.dumps(_p.error_envelope(None, e.code, e.message), sort_keys=True) + "\n")
                stdout.flush()
                continue
            try:
                response = self.handle_message(message)
            except Exception:  # never leak internals; protocol stays alive
                req_id = message.get("id") if isinstance(message, dict) else None
                response = _p.error_envelope(req_id, -32603, "internal error")
            # Interleave progress notifications (if any) BEFORE the response
            # so streamed execution progress precedes the final result. Each
            # is a single-line notification (no "id"); framing stays valid.
            for notification in self.drain_notifications():
                try:
                    stdout.write(json.dumps(notification, sort_keys=True, ensure_ascii=False) + "\n")
                except Exception:
                    pass  # transport best-effort; response below still flows
            if response is not None:
                stdout.write(json.dumps(response, sort_keys=True, ensure_ascii=False) + "\n")
                stdout.flush()
        log_event(request_id="shutdown", audit_id="", tool="server", duration_ms=0, status="stopped")
        return 0


def create_server() -> McpServer:
    """Return the MCP server instance (stdio adapter over Core)."""
    return McpServer()


def run_stdio() -> int:
    return create_server().run_stdio()
