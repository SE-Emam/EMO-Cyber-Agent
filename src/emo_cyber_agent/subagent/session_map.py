"""MCP transport ↔ subagent session mapping — POST-T018.

Maps opaque MCP transport concepts (``progressToken`` / request ids) to
:class:`SubagentSession` records WITHOUT changing the server.

Rules (fail closed, deterministic, side-effect free apart from the
caller-visible in-memory map):

- ``progressToken`` is an opaque correlation string only. It is validated
  for shape (non-empty after strip, ≤256 chars, no control chars) and is
  NEVER authority: presenting a token grants nothing; every attach still
  validates the full ``(audit, project, snapshot)`` binding triple.
- Triple validation goes through ``binding.assert_binding`` when that
  module is importable; otherwise an inline exact-match fallback applies
  (see ``_assert_binding_fallback`` — NOTE: fallback path, same fail-closed
  semantics, kept only for environments where ``binding`` is unavailable).
- Stale (TTL exceeded or snapshot mismatch) → detach the token entry and
  raise a QUARANTINE signal. No partial use of the stale entry.
- Replay of the same token on a different session → DENY (no quarantine
  escalation — the stored chain is intact, the request is a replay).

No sockets, no clock, no randomness, no I/O: the caller supplies ``now``
(an int epoch, seconds) and the map is plain in-memory state.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.subagent.session import SubagentSession
from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError, SecurityDecision

try:  # Preferred triple check; falls back to inline exact-match below.
    from emo_cyber_agent.subagent.binding import assert_binding as _binding_assert_binding
except Exception:  # pragma: no cover - binding module unavailable
    _binding_assert_binding = None  # type: ignore[assignment]

MAX_TOKEN_LENGTH = 256
DEFAULT_TTL_SECONDS = 3600
# Entry cap (L5): reject-new with an explicit error when full. Stale entries
# are reclaimed by TTL expiry on resolve/reattach; callers should also call
# sweep_expired() periodically (TTL sweep) to bound idle growth.
MAX_SESSION_MAP_ENTRIES: int = 1024


class SessionMapCode(StrEnum):
    """Machine-readable session-map failure classes (stable strings)."""

    INVALID_TOKEN = "MCP_SESSION_MAP_INVALID_TOKEN"
    TRIPLE_MISMATCH = "MCP_SESSION_MAP_TRIPLE_MISMATCH"
    STALE_ATTACHMENT = "MCP_SESSION_MAP_STALE_ATTACHMENT"
    REPLAY_DENIED = "MCP_SESSION_MAP_REPLAY_DENIED"
    CAPACITY_EXCEEDED = "MCP_SESSION_MAP_CAPACITY_EXCEEDED"


# SessionMapCode → (host-interop code, quarantine?, security decision).
_MAP_WIRING: dict[SessionMapCode, tuple[HostErrorCode, bool, SecurityDecision]] = {
    SessionMapCode.INVALID_TOKEN: (HostErrorCode.INVALID, False, SecurityDecision.DENY),
    SessionMapCode.TRIPLE_MISMATCH: (HostErrorCode.SESSION_MISMATCH, True, SecurityDecision.QUARANTINE),
    SessionMapCode.STALE_ATTACHMENT: (HostErrorCode.EXPIRED, True, SecurityDecision.QUARANTINE),
    SessionMapCode.REPLAY_DENIED: (HostErrorCode.INVALID, False, SecurityDecision.DENY),
    SessionMapCode.CAPACITY_EXCEEDED: (HostErrorCode.INVALID, False, SecurityDecision.DENY),
}


class SessionMapError(HostIntegrationError):
    """Session-map failure. Fail closed; never carries usable data."""

    def __init__(self, code: SessionMapCode, message: str, *, reason: str = "") -> None:
        host_code, quarantine, decision = _MAP_WIRING[code]
        super().__init__(host_code, f"{code.value}: {message}", reason=reason, quarantine=quarantine)
        self.map_code = code
        self.decision = decision

    def requires_quarantine(self) -> bool:
        return self.decision == SecurityDecision.QUARANTINE


def _is_control_char(ch: str) -> bool:
    o = ord(ch)
    return o < 0x20 or o == 0x7F


def validate_mcp_token(token: str) -> str:
    """Validate an MCP progressToken / request-id correlation string.

    Shape only: must be ``str``, non-empty after stripping whitespace,
    ``<= MAX_TOKEN_LENGTH`` chars, with no control characters. Returns the
    token unchanged. Raises :class:`SessionMapError` (``INVALID_TOKEN`` →
    DENY, no quarantine) on any shape violation, :class:`TypeError` for
    non-str input.
    """
    if not isinstance(token, str):
        raise TypeError(f"mcp token must be str, got {type(token).__name__}")
    if not token.strip():
        raise SessionMapError(SessionMapCode.INVALID_TOKEN, "empty mcp token", reason="token must be non-empty")
    if len(token) > MAX_TOKEN_LENGTH:
        raise SessionMapError(
            SessionMapCode.INVALID_TOKEN,
            "mcp token too long",
            reason=f"len={len(token)} max={MAX_TOKEN_LENGTH}",
        )
    if any(_is_control_char(c) for c in token):
        raise SessionMapError(
            SessionMapCode.INVALID_TOKEN, "mcp token carries control characters", reason="opaque token must be printable"
        )
    return token


def _assert_binding_fallback(
    session: SubagentSession, *, audit_id: str, project_id: str, snapshot_id: str
) -> None:
    """Inline exact-match fallback when ``binding.assert_binding`` is unavailable.

    NOTE: fallback path only — same fail-closed semantics (exact string
    equality, audit → project → snapshot order, mismatch → QUARANTINE).
    """
    if session.audit_id != audit_id:
        raise SessionMapError(
            SessionMapCode.TRIPLE_MISMATCH,
            "session audit binding mismatch (fallback check)",
            reason=f"expected {audit_id!r}",
        )
    if session.project_id != project_id:
        raise SessionMapError(
            SessionMapCode.TRIPLE_MISMATCH,
            "session project binding mismatch (fallback check)",
            reason=f"expected {project_id!r}",
        )
    if session.snapshot_id != snapshot_id:
        raise SessionMapError(
            SessionMapCode.STALE_ATTACHMENT,
            "stale snapshot binding mismatch (fallback check)",
            reason=f"expected {snapshot_id!r}",
        )


def assert_session_binding(
    session: SubagentSession, *, audit_id: str, project_id: str, snapshot_id: str
) -> None:
    """Validate the ``(audit, project, snapshot)`` triple against ``session``.

    Delegates to ``binding.assert_binding`` when available (preserving its
    ``BindingError`` quarantine semantics); otherwise uses the inline
    exact-match fallback. Mismatch → QUARANTINE signal, never partial use.
    """
    if not isinstance(session, SubagentSession):
        raise TypeError(f"session must be SubagentSession, got {type(session).__name__}")
    for name, value in (("audit_id", audit_id), ("project_id", project_id), ("snapshot_id", snapshot_id)):
        if not isinstance(value, str):
            raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if _binding_assert_binding is not None:
        _binding_assert_binding(session, audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id)
        return
    _assert_binding_fallback(session, audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id)


def _check_now(now: int) -> None:
    if not isinstance(now, int) or isinstance(now, bool):
        raise TypeError(f"now must be an int epoch, got {type(now).__name__}")
    if now < 0:
        raise ValueError("now must be >= 0")


def _check_ttl(ttl: int) -> None:
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        raise TypeError(f"ttl must be an int, got {type(ttl).__name__}")
    if ttl <= 0:
        raise ValueError("ttl must be > 0")


class McpSessionAttachment(BaseModel):
    """Frozen record binding one opaque MCP token to one subagent session."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mcp_token_or_id: str = Field(min_length=1, max_length=MAX_TOKEN_LENGTH)
    session_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    attached_at: int = Field(ge=0)
    last_seen: int = Field(ge=0)

    @field_validator("mcp_token_or_id")
    @classmethod
    def _token_shape(cls, v: str) -> str:
        validate_mcp_token(v)
        return v

    def digest(self) -> str:
        return hashlib.sha256(self.to_canonical_json().encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class McpSessionMap:
    """In-memory MCP-token → session attachment map.

    Caller-owned clock: every method that reasons about staleness takes an
    explicit ``now``. No sockets, no threads, no I/O.
    """

    def __init__(self) -> None:
        self._by_token: dict[str, McpSessionAttachment] = {}

    def __len__(self) -> int:
        return len(self._by_token)

    def __contains__(self, token: object) -> bool:
        return isinstance(token, str) and token in self._by_token

    def attach(
        self,
        session: SubagentSession,
        *,
        mcp_token_or_id: str,
        audit_id: str,
        project_id: str,
        snapshot_id: str,
        now: int,
        ttl: int = DEFAULT_TTL_SECONDS,
    ) -> McpSessionAttachment:
        """Attach ``mcp_token_or_id`` (opaque correlation only) to ``session``.

        Validates token shape, then the binding triple (QUARANTINE on
        mismatch), then replay/staleness against any stored entry:

        - same token on a different ``session_id`` → DENY (replay), stored
          entry untouched;
        - stored entry whose TTL expired or whose snapshot differs from the
          presented ``snapshot_id``/``session.snapshot_id`` → detached, then
          QUARANTINE;
        - otherwise stores (or refreshes ``last_seen`` on) the attachment.
        """
        validate_mcp_token(mcp_token_or_id)
        _check_now(now)
        _check_ttl(ttl)
        assert_session_binding(session, audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id)

        existing = self._by_token.get(mcp_token_or_id)
        if existing is not None:
            if existing.session_id != session.session_id:
                raise SessionMapError(
                    SessionMapCode.REPLAY_DENIED,
                    "mcp token replay denied: token bound to a different session",
                    reason=f"token already attached to {existing.session_id!r}",
                )
            self._raise_if_stale(existing, session=session, now=now, ttl=ttl, snapshot_id=snapshot_id)
            refreshed = existing.model_copy(update={"last_seen": now})
            self._by_token[mcp_token_or_id] = refreshed
            return refreshed

        if len(self._by_token) >= MAX_SESSION_MAP_ENTRIES:
            raise SessionMapError(
                SessionMapCode.CAPACITY_EXCEEDED,
                "mcp session map full: reject-new",
                reason=f"entries={len(self._by_token)} max={MAX_SESSION_MAP_ENTRIES}",
            )
        attachment = McpSessionAttachment(
            mcp_token_or_id=mcp_token_or_id,
            session_id=session.session_id,
            host_id=session.host_id,
            audit_id=audit_id,
            project_id=project_id,
            snapshot_id=snapshot_id,
            attached_at=now,
            last_seen=now,
        )
        self._by_token[mcp_token_or_id] = attachment
        return attachment

    def _raise_if_stale(
        self, existing: McpSessionAttachment, *, session: SubagentSession, now: int, ttl: int, snapshot_id: str
    ) -> None:
        """Detach + QUARANTINE when ``existing`` is stale. Returns None if live."""
        if now > existing.last_seen + ttl:
            self._by_token.pop(existing.mcp_token_or_id, None)
            raise SessionMapError(
                SessionMapCode.STALE_ATTACHMENT,
                "mcp attachment TTL exceeded",
                reason=f"last_seen={existing.last_seen} now={now} ttl={ttl}",
            )
        if existing.snapshot_id != snapshot_id or existing.snapshot_id != session.snapshot_id:
            self._by_token.pop(existing.mcp_token_or_id, None)
            raise SessionMapError(
                SessionMapCode.STALE_ATTACHMENT,
                "mcp attachment snapshot mismatch",
                reason=f"attached snapshot {existing.snapshot_id!r} != presented {snapshot_id!r}",
            )
        if existing.audit_id != session.audit_id or existing.project_id != session.project_id or existing.host_id != session.host_id:
            self._by_token.pop(existing.mcp_token_or_id, None)
            raise SessionMapError(
                SessionMapCode.TRIPLE_MISMATCH,
                "mcp attachment scope drift",
                reason="stored scope != session scope",
            )

    def resolve(self, token: str, *, now: int, ttl: int = DEFAULT_TTL_SECONDS) -> McpSessionAttachment:
        """Return the live attachment for ``token``.

        TTL exceeded → detach + QUARANTINE. Unknown token → ``KeyError``.
        Shape-invalid token → ``SessionMapError`` (DENY).
        """
        validate_mcp_token(token)
        _check_now(now)
        _check_ttl(ttl)
        try:
            existing = self._by_token[token]
        except KeyError:
            raise KeyError(f"unknown mcp token: {token!r}") from None
        if now > existing.last_seen + ttl:
            self._by_token.pop(token, None)
            raise SessionMapError(
                SessionMapCode.STALE_ATTACHMENT,
                "mcp attachment TTL exceeded",
                reason=f"last_seen={existing.last_seen} now={now} ttl={ttl}",
            )
        return existing

    def detach(self, token: str) -> bool:
        """Purge the attachment for ``token``. Returns True when one was removed."""
        if not isinstance(token, str):
            raise TypeError(f"mcp token must be str, got {type(token).__name__}")
        return self._by_token.pop(token, None) is not None

    def sweep_expired(self, *, now: int, ttl: int = DEFAULT_TTL_SECONDS) -> int:
        """TTL sweep: detach every entry whose TTL expired at ``now``.

        Returns the number of entries purged. Call periodically to bound
        idle growth alongside the reject-new entry cap.
        """
        _check_now(now)
        _check_ttl(ttl)
        stale = [t for t, a in self._by_token.items() if now > a.last_seen + ttl]
        for t in stale:
            self._by_token.pop(t, None)
        return len(stale)

    def attached_count(self) -> int:
        return len(self._by_token)
