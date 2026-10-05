"""Audit-handoff gate — POST-T018 (Agent 7A).

Final Host-bound gate producing a :class:`ResultEnvelope`: assembles the
handoff from a session + caller-supplied handoff data, enforces the
verification gate, scrubs via ``result_firewall.scrub`` when available,
attaches the provenance chain (audit → snapshot → digest) plus
limitations and compat/health snapshots, and signs the envelope digest
(sha256 over canonical JSON).

Pure, deterministic, no execution: no tool calls, no clocks (``now`` is
caller-supplied), no mutation of inputs.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Mapping, Self

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.subagent.handoff import (
    AuditHandoff,
    HealthSnapshot,
    ProvenanceLink,
    ResultEnvelope,
    ResultStatus,
)
from emo_cyber_agent.subagent.hosts import (
    CompatibilityDecision,
    CompatibilityVerdict,
)
from emo_cyber_agent.subagent.session import (
    SubagentHealth,
    SubagentLifecycle,
    SubagentSession,
)

try:  # result_firewall is present — use scrub(); else inline minimal note.
    from emo_cyber_agent.subagent.result_firewall import scrub as _firewall_scrub
except Exception:  # pragma: no cover - fallback path
    _firewall_scrub = None

SCRUB_UNAVAILABLE_NOTE = "scrub-unavailable:inline-note"

__all__ = [
    "GateStatus",
    "HandoffGateResult",
    "assemble",
    "envelope_digest",
]


class GateStatus(StrEnum):
    COMPLETED = "completed"
    HOLD = "hold"
    QUARANTINED = "quarantined"
    FAILED = "failed"


class HandoffGateResult(BaseModel):
    """Outcome of the handoff gate. Records; permits nothing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: GateStatus
    envelope: ResultEnvelope | None = None
    digest: str = ""
    removed: tuple[str, ...] = ()
    quarantined: bool = False
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def envelope_digest(envelope: ResultEnvelope) -> str:
    """Sign an envelope: sha256 over its canonical JSON. Stable for equal inputs."""
    return _canonical_digest(envelope.to_dict())


def _hold_digest(*, session: SubagentSession, task_id: str, reasons: tuple[str, ...]) -> str:
    return _canonical_digest(
        {
            "status": GateStatus.HOLD.value,
            "session_id": session.session_id,
            "audit_id": session.audit_id,
            "task_id": task_id,
            "reasons": list(reasons),
        }
    )


def _fail_digest(*, session_id: str, audit_id: str, reasons: tuple[str, ...]) -> str:
    return _canonical_digest(
        {
            "status": GateStatus.FAILED.value,
            "session_id": session_id,
            "audit_id": audit_id,
            "reasons": list(reasons),
        }
    )


def _clean_tokens(values: Any) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    cleaned: list[str] = []
    for item in values:
        if not isinstance(item, str):
            continue
        token = item.strip()
        if token:
            cleaned.append(token)
    return tuple(cleaned)


def _scrub_envelope(
    raw: dict[str, Any], *, audit_id: str, trusted_authz_ref: str | None = None
) -> tuple[dict[str, Any], tuple[str, ...], bool]:
    """Run result_firewall.scrub when available, else an inline minimal note."""
    if _firewall_scrub is None:  # pragma: no cover - fallback path
        return dict(raw), (SCRUB_UNAVAILABLE_NOTE,), False
    verdict = _firewall_scrub(raw, audit_id=audit_id, trusted_authz_ref=trusted_authz_ref)
    clean = dict(verdict.clean_result)
    return clean, tuple(verdict.removed), bool(verdict.quarantined)


def assemble(
    session: SubagentSession,
    handoff_data: Mapping[str, Any] | None,
    verification_refs: Any,
    recovery_state: str = "none",
    *,
    task_id: str = "",
    authorization_ref: str = "",
    limitations: Any = (),
    compatibility: CompatibilityDecision | None = None,
    health_note: str = "",
    now: int = 0,
) -> HandoffGateResult:
    """Assemble the final Host-bound ResultEnvelope (no execution).

    Verification gate: empty ``verification_refs`` yields HOLD, never a
    COMPLETED envelope. Provenance chain (audit → snapshot → digest),
    limitations, and compat/health snapshots are attached on success, and
    the envelope digest (sha256 canonical) signs the result.
    """
    if not isinstance(session, SubagentSession):
        reasons = ("invalid: session must be a SubagentSession",)
        return HandoffGateResult(
            status=GateStatus.FAILED,
            envelope=None,
            digest=_fail_digest(session_id="", audit_id="", reasons=reasons),
            removed=(),
            quarantined=False,
            reasons=reasons,
        )

    data: Mapping[str, Any] = handoff_data if isinstance(handoff_data, Mapping) else {}

    resolved_task = (task_id or str(data.get("task_id", "") or "")).strip()
    verified = _clean_tokens(verification_refs)
    if not verified:
        reasons = ("verification-gate-hold: verification_refs empty — HOLD, not COMPLETED",)
        return HandoffGateResult(
            status=GateStatus.HOLD,
            envelope=None,
            digest=_hold_digest(session=session, task_id=resolved_task, reasons=reasons),
            removed=(),
            quarantined=False,
            reasons=reasons,
        )

    if not resolved_task:
        reasons = ("invalid: task_id is required",)
        return HandoffGateResult(
            status=GateStatus.FAILED,
            envelope=None,
            digest=_fail_digest(
                session_id=session.session_id, audit_id=session.audit_id, reasons=reasons
            ),
            removed=(),
            quarantined=False,
            reasons=reasons,
        )

    # Fail closed on caller-supplied binding overrides.
    for key in ("audit_id", "project_id", "snapshot_id"):
        override = data.get(key, "")
        if isinstance(override, str) and override and override != getattr(session, key):
            reasons = (f"cross-audit: handoff {key} binding mismatch — quarantining",)
            clean_fail = {"audit_id": session.audit_id, "status": "quarantined"}
            return HandoffGateResult(
                status=GateStatus.QUARANTINED,
                envelope=None,
                digest=_canonical_digest(clean_fail),
                removed=(f"cross-audit:$.{key}",),
                quarantined=True,
                reasons=reasons,
            )

    if not isinstance(recovery_state, str) or not recovery_state.strip() or len(recovery_state) > 64:
        reasons = ("invalid: recovery_state must be a non-empty string of max 64 chars",)
        return HandoffGateResult(
            status=GateStatus.FAILED,
            envelope=None,
            digest=_fail_digest(
                session_id=session.session_id, audit_id=session.audit_id, reasons=reasons
            ),
            removed=(),
            quarantined=False,
            reasons=reasons,
        )

    authz = (authorization_ref or str(data.get("authorization_ref", "") or "")).strip()
    if not authz:
        authz = f"authz-handoff-{session.session_id}"[:120]
    combined_limitations = _clean_tokens(limitations) + _clean_tokens(data.get("limitations", ()))

    raw: dict[str, Any] = {
        "status": ResultStatus.COMPLETED.value,
        "task_id": resolved_task,
        "session_id": session.session_id,
        "audit_id": session.audit_id,
        "project_id": session.project_id,
        "snapshot_id": session.snapshot_id,
        "handoff": {
            "audit_id": session.audit_id,
            "project_id": session.project_id,
            "snapshot_id": session.snapshot_id,
            "finding_refs": list(_clean_tokens(data.get("finding_refs", ()))),
            "evidence_refs": list(_clean_tokens(data.get("evidence_refs", ()))),
            "verification_refs": list(verified),
            "report_ref": str(data.get("report_ref", "") or ""),
            "limitations": list(combined_limitations),
            "recovery_state": recovery_state.strip(),
            "provenance": [
                {
                    "task_id": resolved_task,
                    "session_id": session.session_id,
                    "authorization_ref": authz,
                    "recorded_at": int(now),
                }
            ],
        },
        "completed_at": int(now),
    }
    # Carry any extra caller keys through the firewall so CoT / raw-output /
    # provider-internal / secret material is stripped (or quarantined) there.
    for key, value in data.items():
        if key in (
            "task_id",
            "finding_refs",
            "evidence_refs",
            "report_ref",
            "limitations",
            "authorization_ref",
            "audit_id",
            "project_id",
            "snapshot_id",
        ):
            continue
        raw[key] = value

    clean, removed, quarantined = _scrub_envelope(
        raw, audit_id=session.audit_id, trusted_authz_ref=authz
    )
    if quarantined:
        reasons = ("cross-audit: firewall quarantined result binding mismatch",)
        return HandoffGateResult(
            status=GateStatus.QUARANTINED,
            envelope=None,
            digest=_canonical_digest(clean),
            removed=removed,
            quarantined=True,
            reasons=reasons,
        )

    try:
        clean_handoff = dict(clean.get("handoff", {}))
        handoff = AuditHandoff(
            audit_id=session.audit_id,
            project_id=session.project_id,
            snapshot_id=session.snapshot_id,
            finding_refs=tuple(_clean_tokens(clean_handoff.get("finding_refs", ()))),
            evidence_refs=tuple(_clean_tokens(clean_handoff.get("evidence_refs", ()))),
            verification_refs=tuple(_clean_tokens(clean_handoff.get("verification_refs", ())) or verified),
            report_ref=str(clean_handoff.get("report_ref", "") or ""),
            limitations=tuple(_clean_tokens(clean_handoff.get("limitations", ()))),
            recovery_state=str(clean_handoff.get("recovery_state", "") or recovery_state).strip(),
            provenance=tuple(
                ProvenanceLink.model_validate(p)
                for p in (clean_handoff.get("provenance", []) or [])
            ),
        )
    except Exception as exc:
        reasons = (f"invalid: cannot build AuditHandoff: {exc}",)
        return HandoffGateResult(
            status=GateStatus.FAILED,
            envelope=None,
            digest=_fail_digest(
                session_id=session.session_id, audit_id=session.audit_id, reasons=reasons
            ),
            removed=removed,
            quarantined=False,
            reasons=reasons,
        )

    compat = compatibility
    if compat is None:
        compat = CompatibilityDecision(
            host_id=session.host_id,
            verdict=CompatibilityVerdict.COMPATIBLE_RANGE,
            host_version="",
            required="",
            reasons=("gate-default: compatible range",),
            evaluated_at=int(now),
        )

    lifecycle_state = session.state if isinstance(session.state, SubagentLifecycle) else SubagentLifecycle.REPORTING
    note = (health_note or str(data.get("health_note", "") or ""))[:300]
    try:
        health = HealthSnapshot(health=session.health, state=lifecycle_state, note=note)
    except Exception as exc:
        reasons = (f"invalid: cannot build HealthSnapshot: {exc}",)
        return HandoffGateResult(
            status=GateStatus.FAILED,
            envelope=None,
            digest=_fail_digest(
                session_id=session.session_id, audit_id=session.audit_id, reasons=reasons
            ),
            removed=removed,
            quarantined=False,
            reasons=reasons,
        )
    # Session health BLOCKED always reflects degraded availability, never trust.
    _ = SubagentHealth  # keep health semantics local; no trust inference.

    try:
        envelope = ResultEnvelope(
            status=ResultStatus.COMPLETED,
            task_id=resolved_task,
            session_id=session.session_id,
            audit_id=session.audit_id,
            project_id=session.project_id,
            snapshot_id=session.snapshot_id,
            handoff=handoff,
            compatibility=compat,
            health=health,
            completed_at=int(now),
        )
        envelope.assert_binding(
            audit_id=session.audit_id,
            project_id=session.project_id,
            snapshot_id=session.snapshot_id,
        )
    except Exception as exc:
        quarantined_exc = getattr(exc, "quarantine", False)
        status = GateStatus.QUARANTINED if quarantined_exc else GateStatus.FAILED
        reasons = (f"{'quarantined' if quarantined_exc else 'invalid'}: cannot seal ResultEnvelope: {exc}",)
        if quarantined_exc:
            return HandoffGateResult(
                status=status,
                envelope=None,
                digest=_canonical_digest({"audit_id": session.audit_id, "status": "quarantined"}),
                removed=removed,
                quarantined=True,
                reasons=reasons,
            )
        return HandoffGateResult(
            status=status,
            envelope=None,
            digest=_fail_digest(
                session_id=session.session_id, audit_id=session.audit_id, reasons=reasons
            ),
            removed=removed,
            quarantined=False,
            reasons=reasons,
        )

    return HandoffGateResult(
        status=GateStatus.COMPLETED,
        envelope=envelope,
        digest=envelope_digest(envelope),
        removed=removed,
        quarantined=False,
        reasons=("handoff-sealed",),
    )
