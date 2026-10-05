"""Session→audit→project→snapshot chain enforcement — POST-T018.

Unified, stateless binding check for subagent sessions. Given a
:class:`SubagentSession` and the ``(audit_id, project_id, snapshot_id)``
triple carried by a request, verifies every link matches the session fields
exactly:

- audit mismatch    → ``SCOPE_MISMATCH`` → QUARANTINE (no partial use)
- project mismatch  → ``SCOPE_MISMATCH`` → QUARANTINE (no partial use)
- snapshot mismatch → ``STALE`` (stale snapshot) → QUARANTINE (no partial use)

Replay guard: :func:`consume_nonce` single-uses caller-held nonces from an
optional nonce set. A reused nonce → DENY (no quarantine escalation — the
chain itself is intact, the request is a replay).

Pure and deterministic: exact string equality (no normalization, no
coercion), no clock, no randomness, no I/O, no execution, no store. Nonce
state is caller-owned (a ``frozenset`` threaded through
:func:`consume_nonce`); durable per-scope storage lives in
``isolation.HostContextStore``. Errors subclass
:class:`HostIntegrationError` so existing ``except HostIntegrationError``
boundaries keep working.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.subagent.session import SubagentSession
from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError, SecurityDecision

MAX_NONCE_LENGTH = 256


class BindingCode(StrEnum):
    """Machine-readable binding failure classes.

    Mirrors the ``MISMATCHED_AUDIT`` / ``STALE_POLICY`` pattern from
    ``core/verification.py``: one code per failure class, stable strings.
    """

    SCOPE_MISMATCH = "SUBAGENT_SCOPE_MISMATCH"
    STALE_SNAPSHOT = "SUBAGENT_STALE_SNAPSHOT"
    REPLAY_DENIED = "SUBAGENT_REPLAY_DENIED"


class BindingField(StrEnum):
    """Which chain link failed. Snapshot staleness is its own class."""

    AUDIT_ID = "audit_id"
    PROJECT_ID = "project_id"
    SNAPSHOT_ID = "snapshot_id"


# BindingCode → (host-interop code, quarantine?, security decision).
_BINDING_WIRING: dict[BindingCode, tuple[HostErrorCode, bool, SecurityDecision]] = {
    BindingCode.SCOPE_MISMATCH: (HostErrorCode.SESSION_MISMATCH, True, SecurityDecision.QUARANTINE),
    BindingCode.STALE_SNAPSHOT: (HostErrorCode.SESSION_MISMATCH, True, SecurityDecision.QUARANTINE),
    BindingCode.REPLAY_DENIED: (HostErrorCode.INVALID, False, SecurityDecision.DENY),
}


class BindingError(HostIntegrationError):
    """Chain or replay failure. Fail closed; never carries usable data."""

    def __init__(self, binding: BindingCode, message: str, *, field: BindingField | str = "", reason: str = "") -> None:
        code, quarantine, decision = _BINDING_WIRING[binding]
        super().__init__(code, f"{binding.value}: {message}", reason=reason, quarantine=quarantine)
        self.binding = binding
        self.field = field.value if isinstance(field, BindingField) else field
        self.decision = decision

    def requires_quarantine(self) -> bool:
        return self.decision == SecurityDecision.QUARANTINE


class BindingAttestation(BaseModel):
    """Proof that all four chain links matched. Returned only on full match."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)

    def digest(self) -> str:
        return hashlib.sha256(self.to_canonical_json().encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _check_session(session: SubagentSession) -> None:
    if not isinstance(session, SubagentSession):
        raise TypeError(f"session must be SubagentSession, got {type(session).__name__}")


def _check_triple(audit_id: str, project_id: str, snapshot_id: str) -> None:
    for name, value in (("audit_id", audit_id), ("project_id", project_id), ("snapshot_id", snapshot_id)):
        if not isinstance(value, str):
            raise TypeError(f"{name} must be str, got {type(value).__name__}")


def bind(session: SubagentSession, *, audit_id: str, project_id: str, snapshot_id: str) -> BindingAttestation:
    """Verify the full session→audit→project→snapshot chain.

    Every link must equal the corresponding session field exactly. The first
    mismatch raises :class:`BindingError` — no attestation, no partial use.
    Check order is fixed (audit → project → snapshot) so failures are
    deterministic.
    """
    _check_session(session)
    _check_triple(audit_id, project_id, snapshot_id)
    if session.audit_id != audit_id:
        raise BindingError(
            BindingCode.SCOPE_MISMATCH,
            "session audit binding mismatch",
            field=BindingField.AUDIT_ID,
            reason=f"expected {audit_id!r}",
        )
    if session.project_id != project_id:
        raise BindingError(
            BindingCode.SCOPE_MISMATCH,
            "session project binding mismatch",
            field=BindingField.PROJECT_ID,
            reason=f"expected {project_id!r}",
        )
    if session.snapshot_id != snapshot_id:
        raise BindingError(
            BindingCode.STALE_SNAPSHOT,
            "stale snapshot binding mismatch",
            field=BindingField.SNAPSHOT_ID,
            reason=f"expected {snapshot_id!r}",
        )
    return BindingAttestation(
        session_id=session.session_id,
        host_id=session.host_id,
        audit_id=session.audit_id,
        project_id=session.project_id,
        snapshot_id=session.snapshot_id,
    )


def assert_binding(session: SubagentSession, *, audit_id: str, project_id: str, snapshot_id: str) -> None:
    """Void check for requests carrying the ``(audit, project, snapshot)`` triple.

    Same fail-closed semantics as :func:`bind`; discards the attestation.
    """
    bind(session, audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id)


def _check_nonce(nonce: str) -> None:
    if not isinstance(nonce, str):
        raise TypeError(f"nonce must be str, got {type(nonce).__name__}")
    if not nonce or len(nonce) > MAX_NONCE_LENGTH:
        raise ValueError(f"nonce must be 1..{MAX_NONCE_LENGTH} chars")


def consume_nonce(seen: frozenset[str], nonce: str) -> frozenset[str]:
    """Single-use consume of a nonce against a caller-owned ``seen`` set.

    Returns a NEW frozenset with ``nonce`` added; ``seen`` is never mutated.
    A reused nonce raises :class:`BindingError` (``REPLAY_DENIED`` → DENY,
    no quarantine — the chain is intact, the request is a replay).
    """
    if not isinstance(seen, frozenset):
        raise TypeError(f"seen must be frozenset[str], got {type(seen).__name__}")
    _check_nonce(nonce)
    if nonce in seen:
        raise BindingError(
            BindingCode.REPLAY_DENIED,
            "replayed nonce denied",
            reason="nonce already consumed (single-use)",
        )
    return seen | {nonce}
