"""Subagent lifecycle runtime coordinator — POST-T018.

A coordinator (not an authority): drives a :class:`SubagentSession` through
:class:`SubagentLifecycle` states and emits coordination DATA records only.
It permits nothing — every state change goes through
``SubagentSession.transition`` (coordination-only by contract), and every
security decision stays in Core / the recovery subsystem.

Determinism: every method takes caller-supplied ``now`` (int ticks); nothing
reads wall clocks, randomness, or model/host text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping

from emo_cyber_agent.subagent.session import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    SubagentLifecycle,
    SubagentSession,
)
from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

# --- Recovery backend: use it if the import is clean, else mirror --- #
try:  # pragma: no cover - import path exercised when recovery is present
    from emo_cyber_agent.recovery import (
        MAX_RECOVERY_ATTEMPTS as _RECOVERY_MAX_ATTEMPTS,
    )
    from emo_cyber_agent.recovery import (
        OUTCOME_BUDGET_EXHAUSTED as _OUTCOME_BUDGET_EXHAUSTED,
    )
    from emo_cyber_agent.recovery import (
        OUTCOME_FAILED_CLOSED as _OUTCOME_FAILED_CLOSED,
    )
    from emo_cyber_agent.recovery import (
        OUTCOME_QUARANTINED as _OUTCOME_QUARANTINED,
    )
    from emo_cyber_agent.recovery import (
        OUTCOME_RECOVERED as _OUTCOME_RECOVERED,
    )
    from emo_cyber_agent.recovery import RecoveryManager, RecoveryRequest

    _RECOVERY_AVAILABLE = True
except Exception:  # pragma: no cover - fallback when recovery is unavailable
    _RECOVERY_MAX_ATTEMPTS = 3
    _OUTCOME_RECOVERED = "RECOVERED"
    _OUTCOME_QUARANTINED = "QUARANTINED"
    _OUTCOME_FAILED_CLOSED = "FAILED_CLOSED"
    _OUTCOME_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    RecoveryManager = None  # type: ignore[assignment,misc]
    RecoveryRequest = None  # type: ignore[assignment,misc]
    _RECOVERY_AVAILABLE = False


class LifecycleRecoveryOutcome(str, Enum):
    """Local mirror of the recovery outcome vocabulary.

    Kept identical to the recovery subsystem strings so coordination records
    stay comparable whether the recovery backend or the mirror produced them.
    """

    RECOVERED = "RECOVERED"
    QUARANTINED = "QUARANTINED"
    FAILED_CLOSED = "FAILED_CLOSED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


#: Upper bound on recovery attempts mirrored from (or into) recovery policy.
MAX_LIFECYCLE_RECOVERY_ATTEMPTS: int = int(_RECOVERY_MAX_ATTEMPTS)


@dataclass(frozen=True)
class CoordinationRecord:
    """DATA-only note of a coordination step. Permits nothing."""

    event: str
    session_id: str
    from_state: str
    to_state: str
    detail: str = ""
    at: int = 0


@dataclass(frozen=True)
class LifecycleResult:
    """Immutable outcome of one coordinator call."""

    session: SubagentSession
    records: tuple[CoordinationRecord, ...] = ()
    ok: bool = False
    reason: str = ""


def _record(
    event: str,
    session_id: str,
    from_state: SubagentLifecycle,
    to_state: SubagentLifecycle,
    *,
    detail: str = "",
    now: int = 0,
) -> CoordinationRecord:
    return CoordinationRecord(
        event=event,
        session_id=session_id,
        from_state=from_state.value,
        to_state=to_state.value,
        detail=str(detail),
        at=int(now),
    )


def _step(
    session: SubagentSession, to: SubagentLifecycle
) -> SubagentSession:
    """Single coordination-only transition. Raises on illegal edges."""
    return session.transition(to)


def _fail_closed(
    session: SubagentSession, *, reason: str, now: int
) -> tuple[SubagentSession, tuple[CoordinationRecord, ...]]:
    """Walk *session* to FAILED along legal edges. Never orphans.

    Direct FAILED edges exist from RUNNING/VERIFYING/REPORTING/RECOVERING.
    STARTING/READY route via UNAVAILABLE -> RECOVERING -> FAILED.
    Terminal sessions are returned untouched with a note record.
    """
    records: list[CoordinationRecord] = []
    current = session
    if current.state == SubagentLifecycle.FAILED:
        records.append(
            _record(
                "timeout-already-failed",
                current.session_id,
                current.state,
                current.state,
                detail=reason,
                now=now,
            )
        )
        return current, tuple(records)
    if current.state in TERMINAL_STATES:
        records.append(
            _record(
                "timeout-terminal-noop",
                current.session_id,
                current.state,
                current.state,
                detail=f"{reason}; terminal state preserved",
                now=now,
            )
        )
        return current, tuple(records)
    # Bridge walk: prefer a direct FAILED edge, else step toward it via
    # UNAVAILABLE / RECOVERING, both of which are legal intermediate stops.
    guard = 0
    while current.state != SubagentLifecycle.FAILED:
        guard += 1
        if guard > 6:  # defense in depth: transition graph is finite
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                "lifecycle timeout walk exceeded bridge budget",
            )
        nxt: SubagentLifecycle | None = None
        allowed = ALLOWED_TRANSITIONS[current.state]
        if SubagentLifecycle.FAILED in allowed:
            nxt = SubagentLifecycle.FAILED
        elif SubagentLifecycle.UNAVAILABLE in allowed:
            nxt = SubagentLifecycle.UNAVAILABLE
        elif SubagentLifecycle.RECOVERING in allowed:
            nxt = SubagentLifecycle.RECOVERING
        else:  # pragma: no cover - no current state lacks all bridges
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                f"no fail-closed bridge from {current.state.value}",
            )
        prev = current
        current = _step(current, nxt)
        records.append(
            _record(
                "timeout-fail-closed" if nxt == SubagentLifecycle.FAILED else "timeout-bridge",
                current.session_id,
                prev.state,
                current.state,
                detail=reason,
                now=now,
            )
        )
    return current, tuple(records)


def _scope_summary(scope: Any) -> str:
    """Deterministic, read-only fingerprint of a bound scope (DATA only)."""
    try:
        data: Any = None
        if hasattr(scope, "to_dict"):
            data = scope.to_dict()
        elif hasattr(scope, "model_dump"):
            data = scope.model_dump(mode="json")
        if isinstance(data, Mapping):
            included = tuple(data.get("included", ()))
            target_types = tuple(data.get("target_types", ()))
            return f"included={list(included)} target_types={list(target_types)}"
        if isinstance(scope, Mapping):
            return (
                f"included={list(scope.get('included', []))} "
                f"target_types={list(scope.get('target_types', []))}"
            )
    except Exception:
        pass
    return f"scope={type(scope).__name__}"


class LifecycleCoordinator:
    """Runtime coordinator driving SubagentSession states.

    Coordination only: records progress, permits nothing, duplicates no
    security authority. Security lifecycle (quarantine, trust, authorization)
    stays in Core; recovery semantics delegate to RecoveryManager.
    """

    def __init__(
        self,
        *,
        executor: Callable[[Any, dict[str, Any]], bool] | None = None,
        max_recovery_attempts: int = MAX_LIFECYCLE_RECOVERY_ATTEMPTS,
    ) -> None:
        self._executor = executor
        # Fail closed on absurd budgets; never exceed the mirrored policy cap.
        self._max_recovery_attempts = max(
            0, min(int(max_recovery_attempts), MAX_LIFECYCLE_RECOVERY_ATTEMPTS)
        )

    @property
    def max_recovery_attempts(self) -> int:
        return self._max_recovery_attempts

    # -- start -------------------------------------------------------- #
    def start(
        self,
        session: SubagentSession,
        *,
        scope: Any,
        delegation_id: str,
        now: int,
    ) -> LifecycleResult:
        """Deterministic STARTING -> READY. Binds scope, records delegation id."""
        if not isinstance(delegation_id, str) or not delegation_id.strip():
            raise HostIntegrationError(
                HostErrorCode.INVALID, "delegation_id must be a non-empty string"
            )
        if session.state != SubagentLifecycle.STARTING:
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                f"start requires STARTING, got {session.state.value}",
            )
        session.assert_live(now=now)  # expired sessions fail closed, never start
        summary = _scope_summary(scope)
        nxt = _step(session, SubagentLifecycle.READY)
        rec = _record(
            "started",
            session.session_id,
            session.state,
            nxt.state,
            detail=f"delegation={delegation_id.strip()} {summary}",
            now=now,
        )
        return LifecycleResult(session=nxt, records=(rec,), ok=True)

    # -- heartbeat / timeout guard ------------------------------------ #
    def heartbeat(
        self, session: SubagentSession, *, now: int, deadline: int
    ) -> LifecycleResult:
        """Liveness guard on caller-supplied ticks.

        Within deadline: session unchanged, alive record emitted.
        Past deadline: session walks to FAILED (no orphan); terminal sessions
        are preserved untouched.
        """
        if now <= deadline:
            rec = _record(
                "heartbeat-ok",
                session.session_id,
                session.state,
                session.state,
                detail=f"now={now} deadline={deadline}",
                now=now,
            )
            return LifecycleResult(session=session, records=(rec,), ok=True)
        failed, records = _fail_closed(
            session,
            reason=f"deadline exceeded now={now} deadline={deadline}",
            now=now,
        )
        return LifecycleResult(
            session=failed,
            records=records,
            ok=failed.state == SubagentLifecycle.FAILED
            and session.state not in TERMINAL_STATES,
            reason=f"deadline exceeded now={now} deadline={deadline}",
        )

    # -- cancel -------------------------------------------------------- #
    def cancel(self, session: SubagentSession, *, now: int, reason: str = "") -> LifecycleResult:
        """Bounded cancel: RUNNING (or READY/VERIFYING) -> CANCELLED.

        Emits a terminal event. Never yields COMPLETED. Terminal sessions are
        preserved untouched; non-cancellable live states raise fail-closed.
        """
        if session.state in TERMINAL_STATES:
            rec = _record(
                "cancel-terminal-noop",
                session.session_id,
                session.state,
                session.state,
                detail=reason or "already terminal; cancel is a no-op",
                now=now,
            )
            return LifecycleResult(session=session, records=(rec,), ok=False, reason=rec.detail)
        if SubagentLifecycle.CANCELLED not in ALLOWED_TRANSITIONS[session.state]:
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                f"cancel not permitted from {session.state.value}",
            )
        nxt = _step(session, SubagentLifecycle.CANCELLED)
        assert nxt.state != SubagentLifecycle.COMPLETED  # cancel never completes
        rec = _record(
            "cancelled",
            session.session_id,
            session.state,
            nxt.state,
            detail=reason or "cancel requested",
            now=now,
        )
        return LifecycleResult(session=nxt, records=(rec,), ok=True)

    # -- recover ------------------------------------------------------- #
    def recover(
        self,
        session: SubagentSession,
        *,
        failure: Any,
        now: int,
        executor: Callable[[Any, dict[str, Any]], bool] | None = None,
    ) -> LifecycleResult:
        """Bounded recovery delegating to RecoveryManager semantics.

        Session must be FAILED (or UNAVAILABLE); it steps to RECOVERING, the
        recovery backend runs within its fixed budget, and the outcome maps
        back to coordination state: RECOVERED -> READY, QUARANTINED ->
        quarantined, FAILED_CLOSED/BUDGET_EXHAUSTED -> FAILED. Fail-closed
        throughout; attempts never exceed the mirrored policy cap.
        """
        run_executor = executor if executor is not None else self._executor
        if session.state not in (
            SubagentLifecycle.FAILED,
            SubagentLifecycle.UNAVAILABLE,
        ):
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                f"recover requires FAILED or UNAVAILABLE, got {session.state.value}",
            )
        recovering = _step(session, SubagentLifecycle.RECOVERING)
        entered = _record(
            "recovering",
            session.session_id,
            session.state,
            recovering.state,
            detail=f"failure={failure!r}",
            now=now,
        )
        if _RECOVERY_AVAILABLE and RecoveryManager is not None:
            manager = (
                RecoveryManager(executor=run_executor)
                if run_executor is not None
                else RecoveryManager()
            )
            report = manager.recover(
                RecoveryRequest(audit_id=session.audit_id, failure=failure)
            )
            outcome = report.outcome
            attempts = report.attempts_made
            note = ""
        else:
            # Mirrored bounded semantics with an explicit note; fail closed.
            outcome = _OUTCOME_FAILED_CLOSED
            attempts = 0
            note = "recovery backend unavailable; mirrored fail-closed semantics"
            if run_executor is not None:  # pragma: no cover - defensive
                succeeded = False
                for _ in range(self._max_recovery_attempts):
                    attempts += 1
                    succeeded = bool(run_executor("FAIL_CLOSED", {}))
                    if succeeded:
                        break
                outcome = (
                    _OUTCOME_RECOVERED if succeeded else _OUTCOME_BUDGET_EXHAUSTED
                )
        if attempts > MAX_LIFECYCLE_RECOVERY_ATTEMPTS:  # pragma: no cover
            raise HostIntegrationError(
                HostErrorCode.INVALID, "recovery exceeded attempt budget"
            )
        if outcome == _OUTCOME_RECOVERED:
            nxt = _step(recovering, SubagentLifecycle.READY)
            event = "recovered-ready"
        elif outcome == _OUTCOME_QUARANTINED:
            nxt = recovering.quarantine()
            event = "recovered-quarantined"
        else:  # FAILED_CLOSED / BUDGET_EXHAUSTED (or unknown -> fail closed)
            nxt = _step(recovering, SubagentLifecycle.FAILED)
            event = "recovery-failed-closed"
        detail = (
            f"outcome={outcome} attempts={attempts}"
            + (f" note={note}" if note else "")
        )
        rec = _record(event, session.session_id, recovering.state, nxt.state, detail=detail, now=now)
        return LifecycleResult(
            session=nxt,
            records=(entered, rec),
            ok=outcome == _OUTCOME_RECOVERED,
            reason=detail,
        )

    # -- complete ------------------------------------------------------ #
    def complete(
        self, session: SubagentSession, *, handoff: Any, now: int
    ) -> LifecycleResult:
        """Gate REPORTING -> COMPLETED on verification refs.

        Missing/empty verification refs: session stays REPORTING with a reason
        record. Non-REPORTING sessions raise fail-closed.
        """
        if session.state != SubagentLifecycle.REPORTING:
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                f"complete requires REPORTING, got {session.state.value}",
            )
        refs = getattr(handoff, "verification_refs", None)
        present = (
            refs is not None
            and len(tuple(refs)) > 0
            and all(bool(r) and bool(str(r).strip()) for r in refs)
        )
        if not present:
            rec = _record(
                "complete-gated",
                session.session_id,
                session.state,
                session.state,
                detail="verification refs missing; staying in REPORTING",
                now=now,
            )
            return LifecycleResult(
                session=session,
                records=(rec,),
                ok=False,
                reason=rec.detail,
            )
        nxt = _step(session, SubagentLifecycle.COMPLETED)
        rec = _record(
            "completed",
            session.session_id,
            session.state,
            nxt.state,
            detail=f"verification_refs={len(tuple(refs))}",
            now=now,
        )
        return LifecycleResult(session=nxt, records=(rec,), ok=True)


__all__ = [
    "CoordinationRecord",
    "LifecycleCoordinator",
    "LifecycleRecoveryOutcome",
    "LifecycleResult",
    "MAX_LIFECYCLE_RECOVERY_ATTEMPTS",
]
