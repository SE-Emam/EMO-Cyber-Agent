"""Opaque checkpoint capture/restore for bounded recovery.

A checkpoint is an opaque, audit-scoped snapshot handle. The payload is treated
as immutable bytes: this module never interprets, merges, or rewrites it, and
never allows a checkpoint from one audit to be restored into another
(cross-audit context reuse is rejected).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Checkpoint:
    """Opaque snapshot handle bound to a single audit."""

    audit_id: str
    label: str
    digest: str  # sha256 over audit_id + label + payload bytes
    size_bytes: int


def _coerce_payload(payload: bytes | bytearray | memoryview) -> bytes:
    if isinstance(payload, memoryview):
        return payload.tobytes()
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    raise TypeError(f"payload must be bytes-like, got {type(payload).__name__}")


def capture(audit_id: str, label: str, payload: bytes | bytearray | memoryview) -> tuple[Checkpoint, bytes]:
    """Capture an opaque checkpoint. Returns (handle, immutable payload copy)."""
    from .errors import CheckpointError

    if not isinstance(audit_id, str) or not audit_id.strip():
        raise CheckpointError("audit_id must be a non-empty string")
    if not isinstance(label, str) or not label.strip():
        raise CheckpointError("label must be a non-empty string")
    try:
        raw = _coerce_payload(payload)
    except TypeError as exc:
        raise CheckpointError(str(exc)) from exc
    digest = hashlib.sha256(audit_id.encode() + b"\x00" + label.encode() + b"\x00" + raw).hexdigest()
    handle = Checkpoint(audit_id=audit_id, label=label, digest=digest, size_bytes=len(raw))
    return handle, bytes(raw)


def restore(handle: Checkpoint, payload: bytes | bytearray | memoryview, *, audit_id: str) -> bytes:
    """Restore a checkpoint payload after verifying audit binding and integrity.

    Raises:
        CheckpointError: on audit mismatch, digest mismatch, or bad types.
        ScopeViolationError: when the checkpoint belongs to another audit.
    """
    from .errors import CheckpointError, ScopeViolationError

    if not isinstance(handle, Checkpoint):
        raise CheckpointError(f"handle must be a Checkpoint, got {type(handle).__name__}")
    if audit_id != handle.audit_id:
        raise ScopeViolationError(
            f"Cross-audit checkpoint restore rejected: checkpoint belongs to "
            f"{handle.audit_id!r}, requested by {audit_id!r}"
        )
    try:
        raw = _coerce_payload(payload)
    except TypeError as exc:
        raise CheckpointError(str(exc)) from exc
    expected = hashlib.sha256(
        handle.audit_id.encode() + b"\x00" + handle.label.encode() + b"\x00" + raw
    ).hexdigest()
    if expected != handle.digest:
        raise CheckpointError("Checkpoint integrity check failed: digest mismatch")
    if len(raw) != handle.size_bytes:
        raise CheckpointError("Checkpoint integrity check failed: size mismatch")
    return bytes(raw)


def describe(handle: Checkpoint) -> dict[str, Any]:
    """Return a DATA-only summary of a checkpoint (no payload content)."""
    return {
        "audit_id": handle.audit_id,
        "label": handle.label,
        "digest": handle.digest,
        "size_bytes": handle.size_bytes,
    }
