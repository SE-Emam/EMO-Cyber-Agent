"""MCP Streamable HTTP transport — POST-T020.

Thin stdlib-only bridge exposing the EXISTING :class:`McpServer` over
``POST /mcp`` JSON-RPC. Composition, not a fork: ``Core`` and the stdio
path are untouched (``server.handle_message`` + ``drain_notifications``
are reused verbatim under a lock so concurrent HTTP requests cannot mix
notification queues).

Wire rules
----------
- ``POST /mcp`` only. ``GET /mcp`` → ``405`` (no SSE-primary); any other
  path → ``404``.
- JSON-RPC ``initialize`` / ``ping`` / ``tools/list`` / ``tools/call``
  are dispatched via ``server.handle_message``. Protocol-level failures
  stay inside a ``200`` JSON-RPC error envelope; transport/security
  failures use HTTP statuses (``400``/``401``/``403``/``404``/``405``/
  ``413``/``440``).
- Queued progress notifications are interleaved SSE-style when the
  client sends ``Accept: text/event-stream`` (``event: notification``
  frames followed by one ``event: message`` frame carrying the response).
  Otherwise they are inlined BEFORE the response as a JSON array
  ``[*notifications, response]`` (mirrors the stdio line interleave);
  with zero notifications the body is the plain response object.
- SSE is only a stream carrier for notifications on the POST response.
  There is no standalone ``GET`` event stream.

Session binding
---------------
- ``Mcp-Session-Id`` header binds the request to a ``SubagentSession``
  triple via ``McpSessionMap``. Unknown token → ``404``; stale/triple
  mismatch → ``440`` with ``{"quarantine": true}``. The request is never
  dispatched on mismatch (never cross-audit). No header → stateless
  request, no triple check.
- Presented triple travels in ``X-Eca-Audit-Id`` /
  ``X-Eca-Project-Id`` / ``X-Eca-Snapshot-Id``. Any one present requires
  all three (partial → ``400``).
- Tokens are opaque correlation only, never authority.

Security
--------
- Host allowlist: ``localhost`` / ``127.0.0.1`` / ``::1`` plus
  configured extras. Mismatch → ``403`` (DNS-rebinding guard).
- Origin: absent → allowed (non-browser); present → its host must be
  allowlisted, else ``403``. ``null`` is rejected.
- Optional Bearer auth via env-var REFERENCE only
  (``bearer_env_var="NAME"`` compares against ``os.environ["NAME"]``;
  no secret ever lives in source/config). Missing/invalid, or a
  configured-but-unset variable, → ``401`` (fail closed, never
  auth-as-authority).
- 1 MiB body cap → ``413``. Threaded stdlib server with socket timeout,
  daemon threads, and clean shutdown (``stop()`` / context manager).

Stdlib only: ``http.server`` + ``threading``. No fastapi/uvicorn import.
"""

from __future__ import annotations

import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from emo_cyber_agent.mcp import protocol as _p
from emo_cyber_agent.mcp.server import McpServer, create_server
from emo_cyber_agent.subagent.binding import BindingError
from emo_cyber_agent.subagent.session import SubagentSession
from emo_cyber_agent.subagent.session_map import (
    McpSessionAttachment,
    McpSessionMap,
    SessionMapError,
    validate_mcp_token,
)
from emo_cyber_agent.subagent.trust import HostIntegrationError

MCP_PATH = "/mcp"
SESSION_HEADER = "Mcp-Session-Id"
AUDIT_HEADER = "X-Eca-Audit-Id"
PROJECT_HEADER = "X-Eca-Project-Id"
SNAPSHOT_HEADER = "X-Eca-Snapshot-Id"
TRIPLE_HEADERS = (AUDIT_HEADER, PROJECT_HEADER, SNAPSHOT_HEADER)

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
DEFAULT_MAX_BODY_BYTES = _p.MAX_MESSAGE_BYTES  # 1 MiB, shared with stdio framing
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_SESSION_TTL_SECONDS = 3600

# Custom status: session binding mismatch / stale attachment. Intentionally
# outside the standard registry; always paired with {"quarantine": true}.
SESSION_MISMATCH_STATUS = 440


def _normalize_host(host_header: str) -> str:
    """Lowercased hostname without port; brackets stripped for IPv6."""
    value = (host_header or "").strip().lower()
    if value.startswith("["):  # [::1]:port
        end = value.find("]")
        return value[1:end] if end != -1 else value
    if value.count(":") == 1:  # name:port / v4:port (not a bare v6 literal)
        value = value.rsplit(":", 1)[0]
    return value


def _origin_host(origin: str) -> str | None:
    try:
        host = urlsplit(origin.strip()).hostname
    except Exception:
        return None
    return host.lower() if host else None


class HttpMcpServer:
    """Owns one ``McpServer`` + one ``McpSessionMap`` behind a threaded HTTP socket."""

    def __init__(
        self,
        server: McpServer | None = None,
        *,
        allowed_hosts: set[str] | frozenset[str] | None = None,
        bearer_env_var: str | None = None,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        request_timeout: float = DEFAULT_TIMEOUT_SECONDS,
        session_ttl: int = DEFAULT_SESSION_TTL_SECONDS,
    ) -> None:
        self._server = server or create_server()
        self._sessions: dict[str, SubagentSession] = {}
        self._session_map = McpSessionMap()
        self._allowed_hosts = frozenset(h.lower() for h in (allowed_hosts or ())) | LOOPBACK_HOSTS
        self._bearer_env_var = bearer_env_var
        self._max_body_bytes = max_body_bytes
        self._request_timeout = request_timeout
        self._session_ttl = session_ttl
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._bind = "127.0.0.1"
        self._port = 0

    # -- session registry -------------------------------------------------
    def register_session(
        self, session: SubagentSession, *, now: int | None = None, ttl: int | None = None
    ) -> McpSessionAttachment:
        """Bind ``session.session_id`` as an MCP session token (opaque, never authority)."""
        at = int(time.time()) if now is None else now
        attachment = self._session_map.attach(
            session,
            mcp_token_or_id=session.session_id,
            audit_id=session.audit_id,
            project_id=session.project_id,
            snapshot_id=session.snapshot_id,
            now=at,
            ttl=self._session_ttl if ttl is None else ttl,
        )
        self._sessions[session.session_id] = session
        return attachment

    def check_session(self, token: str, *, triple: dict[str, str | None]) -> SubagentSession:
        """Resolve + verify a session token. Raises ``_HttpError`` (404/440) on failure."""
        try:
            validate_mcp_token(token)
        except SessionMapError as e:
            raise _HttpError(400, "invalid session token", quarantine=False) from e
        try:
            attachment = self._session_map.resolve(token, now=int(time.time()), ttl=self._session_ttl)
        except SessionMapError as e:
            raise _HttpError(SESSION_MISMATCH_STATUS, str(e), quarantine=True) from e
        except KeyError as e:
            raise _HttpError(404, "unknown session", quarantine=False) from e
        session = self._sessions.get(attachment.session_id)
        if session is None:
            raise _HttpError(404, "unknown session", quarantine=False)
        presented = {k: v for k, v in triple.items() if v is not None}
        if presented and len(presented) != len(TRIPLE_HEADERS):
            raise _HttpError(400, "incomplete session binding triple", quarantine=False)
        if len(presented) == len(TRIPLE_HEADERS):
            try:
                from emo_cyber_agent.subagent.session_map import assert_session_binding

                assert_session_binding(
                    session,
                    audit_id=presented[AUDIT_HEADER],  # type: ignore[index]
                    project_id=presented[PROJECT_HEADER],  # type: ignore[index]
                    snapshot_id=presented[SNAPSHOT_HEADER],  # type: ignore[index]
                )
            except (BindingError, SessionMapError, HostIntegrationError) as e:
                raise _HttpError(
                    SESSION_MISMATCH_STATUS, "session binding mismatch", quarantine=True
                ) from e
        return session

    # -- guards ------------------------------------------------------------
    def check_host(self, host_header: str | None) -> None:
        if _normalize_host(host_header or "") not in self._allowed_hosts:
            raise _HttpError(403, "forbidden host", quarantine=False)

    def check_origin(self, origin: str | None) -> None:
        if origin is None or not origin.strip():
            return  # non-browser client; Host allowlist remains the rebinding guard
        if _origin_host(origin) not in self._allowed_hosts:
            raise _HttpError(403, "foreign origin rejected", quarantine=False)

    def check_auth(self, authorization: str | None) -> None:
        if self._bearer_env_var is None:
            return  # auth not configured: open (localhost-bound) by default
        expected = os.environ.get(self._bearer_env_var, "")
        if not expected:
            # Configured but unset: fail closed, never auth-as-authority.
            raise _HttpError(401, "server auth misconfigured", quarantine=False)
        candidate = (authorization or "").strip()
        if not candidate.startswith("Bearer ") or not hmac.compare_digest(
            candidate, f"Bearer {expected}"
        ):
            raise _HttpError(401, "unauthorized", quarantine=False)

    # -- dispatch (composition: reuse McpServer verbatim) -------------------
    def dispatch(self, message: Any) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        with self._lock:
            try:
                response = self._server.handle_message(message)
            except Exception:
                req_id = message.get("id") if isinstance(message, dict) else None
                response = _p.error_envelope(req_id, -32603, "internal error")
            notifications = self._server.drain_notifications()
        return response, notifications

    # -- lifecycle ----------------------------------------------------------
    @property
    def port(self) -> int:
        return self._port

    @property
    def url(self) -> str:
        return f"http://{self._bind}:{self._port}{MCP_PATH}"

    def start(self, bind: str = "127.0.0.1", port: int = 0, *, allow_remote: bool = False) -> HttpMcpServer:
        _require_local_bind(bind, allow_remote=allow_remote)
        handler = _make_handler(self)
        httpd = ThreadingHTTPServer((bind, port), handler)
        httpd.daemon_threads = True
        httpd.request_queue_size = 64
        httpd.timeout = self._request_timeout
        httpd.owner = self  # type: ignore[attr-defined]
        self._httpd = httpd
        self._bind = bind
        self._port = int(httpd.server_address[1])
        self._thread = threading.Thread(target=httpd.serve_forever, name="mcp-http", daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        """Block serving (for real deployments). Stop via ``stop()`` from another thread."""
        if self._httpd is None:
            raise RuntimeError("server not started")
        self._httpd.serve_forever()

    def stop(self) -> None:
        httpd, thread = self._httpd, self._thread
        self._httpd, self._thread = None, None
        if httpd is not None:
            try:
                httpd.shutdown()
            finally:
                httpd.server_close()
        if thread is not None:
            thread.join(timeout=DEFAULT_TIMEOUT_SECONDS)

    def __enter__(self) -> HttpMcpServer:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()


def _require_local_bind(bind: str, *, allow_remote: bool) -> None:
    if _normalize_host(bind) not in LOOPBACK_HOSTS and not allow_remote:
        raise ValueError(f"refusing non-local bind {bind!r} without allow_remote=True (fail closed)")


class _HttpError(Exception):
    def __init__(self, status: int, message: str, *, quarantine: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.quarantine = quarantine


def _make_handler(owner: HttpMcpServer) -> type[BaseHTTPRequestHandler]:
    class _McpHttpHandler(BaseHTTPRequestHandler):
        server_version = "EmoMcpHttp/0.1"
        protocol_version = "HTTP/1.1"

        # -- routing --
        def do_POST(self) -> None:
            if urlsplit(self.path).path != MCP_PATH:
                self._send_error(404, "not found")
                return
            try:
                owner.check_host(self.headers.get("Host"))
                owner.check_auth(self.headers.get("Authorization"))
                owner.check_origin(self.headers.get("Origin"))
                raw = self._read_body()
                try:
                    message = json.loads(raw.decode("utf-8")) if raw else None
                except (ValueError, UnicodeDecodeError):
                    raise _HttpError(400, "invalid JSON", quarantine=False)
                if message is None:
                    raise _HttpError(400, "empty body", quarantine=False)
                session_id = self._bound_session_id()
                response, notifications = owner.dispatch(message)
                if response is None:
                    self._send_bytes(202, b"", "application/json", session_id)
                    return
                if self._wants_sse():
                    self._send_sse(response, notifications, session_id)
                elif notifications:
                    self._send_json(200, [*notifications, response], session_id)
                else:
                    self._send_json(200, response, session_id)
            except _HttpError as e:
                body: dict[str, Any] = {"error": e.message}
                if e.status == SESSION_MISMATCH_STATUS:
                    body["quarantine"] = True
                    body["code"] = "MCP_SESSION_MAP_TRIPLE_MISMATCH"
                self._send_json(e.status, body, None)
            except BrokenPipeError:
                pass

        def do_GET(self) -> None:
            if urlsplit(self.path).path == MCP_PATH:
                self._send_error(405, "method not allowed; use POST /mcp", allow="POST")
            else:
                self._send_error(404, "not found")

        do_PUT = do_GET
        do_DELETE = do_GET
        do_PATCH = do_GET
        do_HEAD = do_GET
        do_OPTIONS = do_GET

        # -- helpers --
        def _bound_session_id(self) -> str | None:
            token = self.headers.get(SESSION_HEADER)
            if token is None:
                return None
            token = token.strip()
            if not token:
                raise _HttpError(400, "empty session token", quarantine=False)
            triple = {name: self.headers.get(name) for name in TRIPLE_HEADERS}
            owner.check_session(token, triple=triple)
            return token

        def _wants_sse(self) -> bool:
            return "text/event-stream" in (self.headers.get("Accept") or "").lower()

        def _read_body(self) -> bytes:
            length_raw = self.headers.get("Content-Length")
            try:
                length = int(length_raw) if length_raw else 0
            except ValueError:
                raise _HttpError(400, "invalid Content-Length", quarantine=False)
            if length < 0:
                raise _HttpError(400, "invalid Content-Length", quarantine=False)
            if length > owner._max_body_bytes:
                # Drain bounded oversize bodies so the client observes the
                # 413 instead of a connection reset. Absurd lengths
                # (>8x cap) are rejected without draining (DoS bound).
                if length <= owner._max_body_bytes * 8:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                raise _HttpError(413, "body too large", quarantine=False)
            if length == 0:
                return b""
            chunks: list[bytes] = []
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > owner._max_body_bytes:
                raise _HttpError(413, "body too large", quarantine=False)
            return raw

        def _send_json(self, status: int, obj: Any, session_id: str | None) -> None:
            self._send_bytes(status, json.dumps(obj).encode("utf-8"), "application/json", session_id)

        def _send_sse(
            self, response: dict[str, Any], notifications: list[dict[str, Any]], session_id: str | None
        ) -> None:
            frames: list[bytes] = []
            for note in notifications:
                frames.append(
                    b"event: notification\ndata: " + json.dumps(note).encode("utf-8") + b"\n\n"
                )
            frames.append(b"event: message\ndata: " + json.dumps(response).encode("utf-8") + b"\n\n")
            self._send_bytes(status=200, raw=b"".join(frames), ctype="text/event-stream", session_id=session_id)

        def _send_bytes(
            self, status: int, raw: bytes, ctype: str, session_id: str | None = None
        ) -> None:
            try:
                reason = None if status != SESSION_MISMATCH_STATUS else "Session Mismatch"
                self.send_response(status, reason)  # type: ignore[arg-type]
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                if session_id is not None:
                    self.send_header(SESSION_HEADER, session_id)
                self.end_headers()
                if self.command != "HEAD" and raw:
                    self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _send_error(self, status: int, message: str, *, allow: str | None = None) -> None:
            try:
                self.send_response(status)
                body = json.dumps({"error": message}).encode("utf-8")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if allow is not None:
                    self.send_header("Allow", allow)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format: str, *args: Any) -> None:  # noqa: ANN401
            # Sanitized access log: method + path + status only (never headers/body/secrets).
            try:
                import sys

                sys.stderr.write(f"mcp-http {self.command} {urlsplit(self.path).path}\n")
            except Exception:
                pass

    return _McpHttpHandler


def run(
    bind: str = "127.0.0.1",
    port: int = 0,
    *,
    allow_remote: bool = False,
    allowed_hosts: set[str] | frozenset[str] | None = None,
    bearer_env_var: str | None = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    request_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    session_ttl: int = DEFAULT_SESSION_TTL_SECONDS,
    server: McpServer | None = None,
) -> HttpMcpServer:
    """Start a Streamable HTTP bridge on ``(bind, port)`` (started, non-blocking).

    Defaults to localhost. A non-loopback ``bind`` without
    ``allow_remote=True`` raises ``ValueError`` (fail closed). Call
    ``stop()`` (or use as a context manager) for clean shutdown.
    """
    return HttpMcpServer(
        server,
        allowed_hosts=allowed_hosts,
        bearer_env_var=bearer_env_var,
        max_body_bytes=max_body_bytes,
        request_timeout=request_timeout,
        session_ttl=session_ttl,
    ).start(bind, port, allow_remote=allow_remote)
