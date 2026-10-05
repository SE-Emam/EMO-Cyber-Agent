"""Subagent lifecycle -> delegation progress bridge — POST-T018.

Coordination-only, advisory-only integration between the subagent session
lifecycle (:class:`SubagentLifecycle`) and the delegation progress
vocabulary (``DELEGATED/INITIALIZING/COLLECTING/ANALYZING/VERIFYING/
REPORTING/RECOVERING/COMPLETED/FAILED/CANCELLED``).

Contract:

* The bridge maps every :class:`SubagentLifecycle` state to a fixed
  progress ``phase`` name plus a fixed ``message_code`` and emits a
  :class:`ProgressEvent` **via the existing** :class:`ProgressState` /
  :class:`ProgressReporter` machinery. It defines no second event system.
* Every emitted event is advisory-only: each ``message_code`` carries an
  ``ADVISORY`` marker, the event carries no authorization, capability, or
  trust fields, and the bridge never transitions the session, never
  quarantines, never permits anything. Security-state decisions stay in
  Core / the recovery subsystem; progress must never drive them.
* Terminal mapping: ``COMPLETED`` always yields ``percent == 100.0`` with
  ``completed == total``; ``FAILED``/``CANCELLED`` (and the
  ``QUARANTINED``-as-``FAILED`` advisory reflection) preserve terminal
  status instead of advancing work.
* Determinism: ``bridge`` is a pure function of ``(session ids,
  lifecycle_state)`` apart from the event timestamp (which
  :class:`ProgressEvent.__eq__` already ignores). Repeating a call with a
  fresh state yields an equal event.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.progress.events import ProgressEvent, ProgressEventType
from emo_cyber_agent.progress.reporter import ProgressReporter
from emo_cyber_agent.progress.state import ProgressState
from emo_cyber_agent.subagent.session import SubagentLifecycle

#: Delegation progress vocabulary. Fixed order; ``phase_index`` values and
#: positional percents derive from it. ``ANALYZING`` is a first-class
#: vocabulary member reserved for downstream collection/analysis detail;
#: the coarse ``SubagentLifecycle.RUNNING`` state reports as ``COLLECTING``
#: (see mapping note below).
DELEGATION_PHASES: tuple[str, ...] = (
    "DELEGATED",
    "INITIALIZING",
    "COLLECTING",
    "ANALYZING",
    "VERIFYING",
    "REPORTING",
    "RECOVERING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
)

#: Progress phases considered terminal. Percent alone never decides
#: anything; consumers must branch on ``phase``/``status``.
TERMINAL_PROGRESS_PHASES: frozenset[str] = frozenset(
    {"COMPLETED", "FAILED", "CANCELLED"}
)

# Lifecycle -> (progress phase, fixed message code, event type).
# Advisory-only: every message code carries the ADVISORY marker and no
# entry carries authorization/capability semantics.
# Notes:
# - RUNNING is coarse work: deterministically reported as COLLECTING.
#   ANALYZING stays a valid vocabulary phase for finer-grained emitters.
# - QUARANTINED is a Core security decision, never a progress decision:
#   reflected advisory-only as FAILED with a distinct message code so the
#   security origin stays visible without authorizing anything.
# - UNAVAILABLE (technically unreachable) is reflected advisory-only as
#   RECOVERING intent, again with a distinct code and no authorization.
_LIFECYCLE_SPEC: dict[SubagentLifecycle, tuple[str, str, ProgressEventType]] = {
    SubagentLifecycle.STARTING: (
        "DELEGATED",
        "SUBAGENT_DELEGATED_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.READY: (
        "INITIALIZING",
        "SUBAGENT_INITIALIZING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.RUNNING: (
        "COLLECTING",
        "SUBAGENT_COLLECTING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.VERIFYING: (
        "VERIFYING",
        "SUBAGENT_VERIFYING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.REPORTING: (
        "REPORTING",
        "SUBAGENT_REPORTING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.RECOVERING: (
        "RECOVERING",
        "SUBAGENT_RECOVERING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.COMPLETED: (
        "COMPLETED",
        "SUBAGENT_COMPLETED_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.FAILED: (
        "FAILED",
        "SUBAGENT_FAILED_ADVISORY",
        ProgressEventType.ERROR,
    ),
    SubagentLifecycle.CANCELLED: (
        "CANCELLED",
        "SUBAGENT_CANCELLED_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.QUARANTINED: (
        "FAILED",
        "SUBAGENT_QUARANTINED_ADVISORY",
        ProgressEventType.ERROR,
    ),
    SubagentLifecycle.UNAVAILABLE: (
        "RECOVERING",
        "SUBAGENT_UNAVAILABLE_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
}

#: Public read-only view: lifecycle state -> progress vocabulary phase.
LIFECYCLE_TO_PROGRESS_PHASE: dict[SubagentLifecycle, str] = {
    state: spec[0] for state, spec in _LIFECYCLE_SPEC.items()
}


def delegation_phases() -> list[str]:
    """Return the delegation progress vocabulary in canonical order."""
    return list(DELEGATION_PHASES)


def progress_state_for(session: Any) -> ProgressState:
    """Create a fresh :class:`ProgressState` bound to *session* ids.

    Uses the delegation vocabulary as the phase list and the session's
    ``session_id``/``audit_id`` as ``run_id``/``audit_id``. Creates state
    only; emits nothing.
    """
    run_id = getattr(session, "session_id", None)
    audit_id = getattr(session, "audit_id", None)
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("session.session_id must be a non-empty string")
    if not isinstance(audit_id, str) or not audit_id.strip():
        raise ValueError("session.audit_id must be a non-empty string")
    return ProgressState(
        run_id=run_id,
        audit_id=audit_id,
        phases=list(DELEGATION_PHASES),
    )


def _coerce_lifecycle(lifecycle_state: Any) -> SubagentLifecycle:
    if isinstance(lifecycle_state, SubagentLifecycle):
        return lifecycle_state
    if isinstance(lifecycle_state, str):
        try:
            return SubagentLifecycle(lifecycle_state.strip().lower())
        except ValueError:
            raise ValueError(
                f"Unknown lifecycle state: {lifecycle_state!r}"
            ) from None
    raise ValueError(f"Unknown lifecycle state: {lifecycle_state!r}")


def bridge(
    session: Any,
    lifecycle_state: SubagentLifecycle | str,
    *,
    state: ProgressState | None = None,
    reporter: ProgressReporter | None = None,
) -> ProgressEvent:
    """Map a subagent lifecycle state to a delegation ProgressEvent.

    Advisory-only: the returned event records coordination progress and
    permits nothing. The session is only read (never transitioned,
    quarantined, or otherwise mutated); security-state decisions must
    never be derived from the event.

    Terminal mapping: ``COMPLETED`` always yields ``percent == 100.0``
    with ``completed == total``; ``FAILED``/``CANCELLED`` (and the
    ``QUARANTINED``-as-``FAILED`` reflection) preserve terminal phase
    status with no further work advanced.

    Emission reuses the existing machinery: the event is produced via
    ``ProgressState.advance`` and, when *reporter* is given, fanned out
    via ``ProgressReporter.report``. No second event system is defined.
    """
    lifecycle = _coerce_lifecycle(lifecycle_state)
    try:
        phase, message_code, event_type = _LIFECYCLE_SPEC[lifecycle]
    except KeyError:
        raise ValueError(f"Unmapped lifecycle state: {lifecycle!r}") from None

    progress = state if state is not None else progress_state_for(session)
    if list(progress.phases) != list(DELEGATION_PHASES):
        raise ValueError(
            "ProgressState phases must equal the delegation progress vocabulary; "
            "the bridge defines no second phase list"
        )

    target_index = DELEGATION_PHASES.index(phase)
    total = progress.total
    if phase == "COMPLETED":
        # Terminal: COMPLETED is always 100% (completed == total).
        target_completed = total
    else:
        target_completed = min(target_index + 1, total)
    # Deterministic positional progress regardless of call history:
    # pre-position so advance() lands exactly on target_completed.
    progress.current_phase_index = target_index
    progress.completed = max(0, min(target_completed - 1, total))

    event = progress.advance(
        phase=phase,
        status=phase,
        message_code=message_code,
        event_type=event_type,
    )
    if reporter is not None:
        reporter.report(event)
    return event


__all__ = [
    "DELEGATION_PHASES",
    "LIFECYCLE_TO_PROGRESS_PHASE",
    "TERMINAL_PROGRESS_PHASES",
    "bridge",
    "delegation_phases",
    "progress_state_for",
]
