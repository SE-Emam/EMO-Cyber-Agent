"""Host-context isolation store — POST-T018.

Binds host-sourced context chunks to exactly one scope:

    ``(host_id, audit_id, project_id, snapshot_id)``

Rules (fail closed, deterministic, side-effect free):

- :meth:`HostContextStore.attach` stores a chunk only when every binding
  field matches the owning scope (``chunk.source == scope.host_id`` and
  audit/project/snapshot equal). Any mismatch raises :class:`ScopeViolation`
  (BLOCK + QUARANTINE): nothing is stored and the scope is marked
  quarantined — later reads/attaches to that scope keep raising until the
  scope is purged via :meth:`HostContextStore.detach`.
- :meth:`HostContextStore.read` returns stored chunks only when the
  caller-supplied ``audit_id`` equals ``scope.audit_id``. Any cross-scope
  read raises :class:`ScopeViolation` and returns no data.
- Per-host partitioning: the store is keyed by the full 4-tuple. Scopes
  never share, merge, or spill into each other.
- Bounded store: ``max_chunks`` (chunk count per scope) and ``max_bytes``
  (UTF-8 bytes of ``chunk.text`` per scope). Eviction choice: FIFO
  **within the owning scope only** — the attaching scope evicts its own
  oldest chunks first. Global pressure never evicts another scope's data.
  A single chunk larger than ``max_bytes`` is rejected outright
  (:class:`IsolationBoundExceeded`) and nothing is buffered.
- Session end → purge: :meth:`HostContextStore.detach` (or
  :meth:`HostContextStore.end_session`) removes every chunk for that scope
  and clears its quarantine flag so a fresh session may start clean.

No execution, no shell, no network, no policy mutation — only ``re``,
``json`` and ``pydantic`` plus the frozen ``HostContextChunk`` DATA model.
"""

from __future__ import annotations

import json
import re
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.subagent.firewall import HostContextChunk
from emo_cyber_agent.subagent.session import SubagentSession
from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

_SCOPE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")

MAX_SCOPED_CHUNKS: int = 128
MAX_SCOPED_BYTES: int = 256 * 1024


class ScopeViolation(HostIntegrationError):
    """Cross-scope or mismatched-binding access. BLOCK + QUARANTINE.

    Always carries ``quarantine=True`` and ``blocked=True``; no data is
    returned alongside it — callers receive the exception instead of bytes.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str = "",
        code: HostErrorCode = HostErrorCode.CROSS_AUDIT,
    ) -> None:
        super().__init__(code, message, reason=reason, quarantine=True)
        self.blocked = True


class IsolationBoundExceeded(HostIntegrationError):
    """Single chunk or bound configuration exceeds the bounded store limits."""

    def __init__(self, message: str, *, reason: str = "") -> None:
        super().__init__(HostErrorCode.INVALID, message, reason=reason, quarantine=False)
        self.blocked = True


class HostScope(BaseModel):
    """Frozen isolation scope. Every chunk is bound to exactly one of these."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_id: str = Field(...)
    audit_id: str = Field(min_length=1, max_length=200)
    project_id: str = Field(min_length=1, max_length=200)
    snapshot_id: str = Field(min_length=1, max_length=200)

    @field_validator("host_id")
    @classmethod
    def _host_kebab(cls, v: str) -> str:
        if not _SCOPE_ID_RE.match(v):
            raise ValueError("host_id must be kebab-case")
        return v

    def key(self) -> tuple[str, str, str, str]:
        return (self.host_id, self.audit_id, self.project_id, self.snapshot_id)

    @classmethod
    def from_session(cls, session: SubagentSession) -> Self:
        if not isinstance(session, SubagentSession):
            raise TypeError(f"session must be SubagentSession, got {type(session).__name__}")
        return cls(
            host_id=session.host_id,
            audit_id=session.audit_id,
            project_id=session.project_id,
            snapshot_id=session.snapshot_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _chunk_bytes(chunk: HostContextChunk) -> int:
    return len(chunk.text.encode("utf-8"))


class HostContextStore:
    """Bounded, per-scope partitioned store for host-sourced context."""

    def __init__(self, *, max_chunks: int = MAX_SCOPED_CHUNKS, max_bytes: int = MAX_SCOPED_BYTES) -> None:
        if not isinstance(max_chunks, int) or isinstance(max_chunks, bool):
            raise TypeError("max_chunks must be an int")
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
            raise TypeError("max_bytes must be an int")
        if max_chunks <= 0:
            raise ValueError("max_chunks must be > 0")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be > 0")
        self._max_chunks = max_chunks
        self._max_bytes = max_bytes
        self._chunks: dict[tuple[str, str, str, str], list[HostContextChunk]] = {}
        self._bytes: dict[tuple[str, str, str, str], int] = {}
        self._quarantined: set[tuple[str, str, str, str]] = set()

    @property
    def max_chunks(self) -> int:
        return self._max_chunks

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    def is_quarantined(self, scope: HostScope) -> bool:
        if not isinstance(scope, HostScope):
            raise TypeError(f"scope must be HostScope, got {type(scope).__name__}")
        return scope.key() in self._quarantined

    def _quarantine(self, key: tuple[str, str, str, str]) -> None:
        self._quarantined.add(key)

    def _assert_usable(self, scope: HostScope) -> tuple[str, str, str, str]:
        key = scope.key()
        if key in self._quarantined:
            raise ScopeViolation(
                "scope is quarantined after a prior violation; purge via detach",
                reason=f"scope={key!r}",
                code=HostErrorCode.SCOPE_WIDENING,
            )
        return key

    @staticmethod
    def _check_attach_binding(scope: HostScope, chunk: HostContextChunk) -> None:
        if chunk.audit_id != scope.audit_id:
            raise ScopeViolation(
                "cross-audit attach rejected",
                reason=f"chunk audit {chunk.audit_id!r} != scope audit {scope.audit_id!r}",
                code=HostErrorCode.CROSS_AUDIT,
            )
        if chunk.source != scope.host_id:
            raise ScopeViolation(
                "cross-host attach rejected",
                reason=f"chunk source {chunk.source!r} != scope host {scope.host_id!r}",
                code=HostErrorCode.BINDING_MISMATCH,
            )
        if chunk.project_id != scope.project_id:
            raise ScopeViolation(
                "cross-project attach rejected",
                reason=f"chunk project {chunk.project_id!r} != scope project {scope.project_id!r}",
                code=HostErrorCode.BINDING_MISMATCH,
            )
        if chunk.snapshot_id != scope.snapshot_id:
            raise ScopeViolation(
                "cross-snapshot attach rejected",
                reason=f"chunk snapshot {chunk.snapshot_id!r} != scope snapshot {scope.snapshot_id!r}",
                code=HostErrorCode.BINDING_MISMATCH,
            )

    def attach(self, scope: HostScope, chunk: HostContextChunk) -> int:
        """Store one chunk under ``scope``. Returns stored count for scope."""
        if not isinstance(scope, HostScope):
            raise TypeError(f"scope must be HostScope, got {type(scope).__name__}")
        if not isinstance(chunk, HostContextChunk):
            raise TypeError(f"chunk must be HostContextChunk, got {type(chunk).__name__}")
        key = scope.key()
        if key in self._quarantined:
            raise ScopeViolation(
                "scope is quarantined after a prior violation; purge via detach",
                reason=f"scope={key!r}",
                code=HostErrorCode.SCOPE_WIDENING,
            )
        try:
            self._check_attach_binding(scope, chunk)
        except ScopeViolation:
            self._quarantine(key)
            raise
        size = _chunk_bytes(chunk)
        if size > self._max_bytes:
            raise IsolationBoundExceeded(
                "chunk exceeds per-scope byte bound; rejected without buffering",
                reason=f"chunk_bytes={size} max_bytes={self._max_bytes}",
            )
        buf = self._chunks.setdefault(key, [])
        used = self._bytes.get(key, 0)
        # Evict oldest within THIS scope only until both bounds fit.
        while (len(buf) >= self._max_chunks or used + size > self._max_bytes) and buf:
            evicted = buf.pop(0)
            used -= _chunk_bytes(evicted)
        buf.append(chunk)
        used += size
        self._bytes[key] = used
        return len(buf)

    def read(self, scope: HostScope, audit_id: str) -> tuple[HostContextChunk, ...]:
        """Return stored chunks for ``scope``. No data on any violation."""
        if not isinstance(scope, HostScope):
            raise TypeError(f"scope must be HostScope, got {type(scope).__name__}")
        if not isinstance(audit_id, str):
            raise TypeError(f"audit_id must be str, got {type(audit_id).__name__}")
        if scope.audit_id != audit_id:
            self._quarantine(scope.key())
            raise ScopeViolation(
                "cross-audit read rejected",
                reason=f"scope audit {scope.audit_id!r} != requested {audit_id!r}",
                code=HostErrorCode.CROSS_AUDIT,
            )
        key = scope.key()
        if key in self._quarantined:
            raise ScopeViolation(
                "scope is quarantined after a prior violation; purge via detach",
                reason=f"scope={key!r}",
                code=HostErrorCode.SCOPE_WIDENING,
            )
        return tuple(self._chunks.get(key, []))

    def detach(self, scope: HostScope) -> int:
        """Purge every chunk for ``scope``. Returns purged count."""
        if not isinstance(scope, HostScope):
            raise TypeError(f"scope must be HostScope, got {type(scope).__name__}")
        key = scope.key()
        buf = self._chunks.pop(key, [])
        self._bytes.pop(key, None)
        self._quarantined.discard(key)
        return len(buf)

    def end_session(self, session: SubagentSession) -> int:
        """Purge the scope owned by ``session`` (session end → purge)."""
        return self.detach(HostScope.from_session(session))

    def scope_chunk_count(self, scope: HostScope) -> int:
        if not isinstance(scope, HostScope):
            raise TypeError(f"scope must be HostScope, got {type(scope).__name__}")
        return len(self._chunks.get(scope.key(), []))

    def scope_byte_count(self, scope: HostScope) -> int:
        if not isinstance(scope, HostScope):
            raise TypeError(f"scope must be HostScope, got {type(scope).__name__}")
        return self._bytes.get(scope.key(), 0)
