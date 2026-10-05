"""Host-integration failure -> RecoveryManager bridge — POST-T018 (Agent 6C).

Coordination-only glue between subagent host-integration failures and the
existing bounded recovery subsystem. The bridge:

* maps host failure kinds (transport / timeout / malformed / session-stale /
  tool-unavailable / host-scope-mismatch, plus the fail-closed trio
  policy-denied / integrity-failure / scope-mismatch) onto the existing
  :class:`~emo_cyber_agent.recovery.classification.FailureClassification`
  set — it defines no second taxonomy and no second policy;
* reuses :class:`~emo_cyber_agent.recovery.manager.RecoveryManager` and
  :func:`~emo_cyber_agent.recovery.policy.decide` verbatim, so attempt
  budgets are inherited (never exceed ``MAX_RECOVERY_ATTEMPTS``) and the
  fail-closed trio (``POLICY_DENIED`` / ``INTEGRITY_FAILURE`` /
  ``SCOPE_MISMATCH``) maps to ``FAIL_CLOSED`` / ``QUARANTINE`` with zero
  attempts and is never retried;
* maps recovery outcomes back to coordination-only session transitions:
  ``RECOVERED`` -> resume (``RECOVERING`` -> ``READY``),
  ``QUARANTINED`` -> quarantined, ``FAILED_CLOSED`` / ``BUDGET_EXHAUSTED``
  -> ``FAILED``;
* mutates nothing else: no policy / finding / evidence mutation and no
  privilege change. Findings, evidence, policy engines, and privileges are
  not even accepted as parameters; the optional ``context`` mapping is
  snapshotted read-only and the input session is never mutated in place
  (``SubagentSession`` transitions return new objects).

Determinism: ``now`` is caller-supplied; nothing reads clocks or randomness.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable, Mapping

from emo_cyber_agent.recovery.actions import RecoveryAction
from emo_cyber_agent.recovery.classification import (
    FailureClassification,
    classify_or_unknown,
)
from emo_cyber_agent.recovery.manager import (
    OUTCOME_BUDGET_EXHAUSTED,
    OUTCOME_FAILED_CLOSED,
    OUTCOME_QUARANTINED,
    OUTCOME_RECOVERED,
    RecoveryManager,
    RecoveryRequest,
)
from emo_cyber_agent.recovery.policy import MAX_RECOVERY_ATTEMPTS, decide
from emo_cyber_agent.recovery.reporting import RecoveryReport
from emo_cyber_agent.subagent.session import SubagentLifecycle, SubagentSession
from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

#: Upper bound inherited from the recovery policy. The bridge never exceeds it.
MAX_BRIDGE_ATTEMPTS: int = MAX_RECOVERY_ATTEMPTS

#: Classifications that must never be retried (fail closed / quarantine).
FAIL_CLOSED_CLASSIFICATIONS: frozenset[FailureClassification] = frozenset(
    {
        FailureClassification.POLICY_DENIED,
        FailureClassification.INTEGRITY_FAILURE,
        FailureClassification.SCOPE_MISMATCH,
    }
)

#: Session states the bridge accepts as a recovery entry point.
RECOVERABLE_STATES: frozenset[SubagentLifecycle] = frozenset(
    {SubagentLifecycle.FAILED, SubagentLifecycle.UNAVAILABLE}
)


class HostFailureKind(StrEnum):
    """Closed host-integration failure vocabulary (DATA labels, not instructions)."""

    TRANSPORT = "transport"
    TIMEOUT = "timeout"
    MALFORMED = "malformed"
    SESSION_STALE = "session-stale"
    TOOL_UNAVAILABLE = "tool-unavailable"
    HOST_SCOPE_MISMATCH = "host-scope-mismatch"
    POLICY_DENIED = "policy-denied"
    INTEGRITY_FAILURE = "integrity-failure"
    SCOPE_MISMATCH = "scope-mismatch"


#: Host failure -> existing FailureClassification. Reuse, don't rebuild:
#: every value is a member of the existing taxonomy.
HOST_FAILURE_TO_CLASSIFICATION: dict[HostFailureKind, FailureClassification] = {
    HostFailureKind.TRANSPORT: FailureClassification.TRANSIENT,
    HostFailureKind.TIMEOUT: FailureClassification.TRANSIENT,
    HostFailureKind.MALFORMED: FailureClassification.MALFORMED_OUTPUT,
    HostFailureKind.SESSION_STALE: FailureClassification.STALE_CONTEXT,
    HostFailureKind.TOOL_UNAVAILABLE: FailureClassification.PROVIDER_UNAVAILABLE,
    HostFailureKind.HOST_SCOPE_MISMATCH: FailureClassification.SCOPE_MISMATCH,
    HostFailureKind.POLICY_DENIED: FailureClassification.POLICY_DENIED,
    HostFailureKind.INTEGRITY_FAILURE: FailureClassification.INTEGRITY_FAILURE,
    HostFailureKind.SCOPE_MISMATCH: FailureClassification.SCOPE_MISMATCH,
}

#: HostIntegrationError code -> existing FailureClassification. Quarantine-flagged
#: scope families map to SCOPE_MISMATCH (QUARANTINE); authz forgeries to
#: POLICY_DENIED; incompatible hosts to INTEGRITY_FAILURE; expiry to
#: STALE_CONTEXT (bounded refresh); anything else fails closed via UNKNOWN.
HOST_ERROR_CODE_TO_CLASSIFICATION: dict[HostErrorCode, FailureClassification] = {
    HostErrorCode.SESSION_MISMATCH: FailureClassification.SCOPE_MISMATCH,
    HostErrorCode.BINDING_MISMATCH: FailureClassification.SCOPE_MISMATCH,
    HostErrorCode.SCOPE_WIDENING: FailureClassification.SCOPE_MISMATCH,
    HostErrorCode.CROSS_AUDIT: FailureClassification.SCOPE_MISMATCH,
    HostErrorCode.CAPABILITY_WIDENING: FailureClassification.SCOPE_MISMATCH,
    HostErrorCode.CAPABILITY_DENIED: FailureClassification.POLICY_DENIED,
    HostErrorCode.AUTHZ_FORGED: FailureClassification.POLICY_DENIED,
    HostErrorCode.COMPAT_INCOMPATIBLE: FailureClassification.INTEGRITY_FAILURE,
    HostErrorCode.COMPAT_UNKNOWN: FailureClassification.UNKNOWN,
    HostErrorCode.EXPIRED: FailureClassification.STALE_CONTEXT,
    HostErrorCode.INVALID: FailureClassification.UNKNOWN,
}


def _normalize_label(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace(" ", "-")


#: Normalized string alias -> FailureClassification. Host-kind labels first,
#: then the raw recovery taxonomy tokens (so "TRANSIENT", "malformed-output",
#: etc. also work). Anything absent falls through to UNKNOWN (fail closed).
_HOST_ALIAS_MAP: dict[str, FailureClassification] = {
    "transport": FailureClassification.TRANSIENT,
    "timeout": FailureClassification.TRANSIENT,
    "malformed": FailureClassification.MALFORMED_OUTPUT,
    "session-stale": FailureClassification.STALE_CONTEXT,
    "stale-context": FailureClassification.STALE_CONTEXT,
    "tool-unavailable": FailureClassification.PROVIDER_UNAVAILABLE,
    "provider-unavailable": FailureClassification.PROVIDER_UNAVAILABLE,
    "host-scope-mismatch": FailureClassification.SCOPE_MISMATCH,
    "scope-mismatch": FailureClassification.SCOPE_MISMATCH,
    "policy-denied": FailureClassification.POLICY_DENIED,
    "integrity-failure": FailureClassification.INTEGRITY_FAILURE,
    "transient": FailureClassification.TRANSIENT,
    "malformed-output": FailureClassification.MALFORMED_OUTPUT,
    "resource-exhausted": FailureClassification.RESOURCE_EXHAUSTED,
    "dependency-mismatch": FailureClassification.DEPENDENCY_MISMATCH,
    "unknown": FailureClassification.UNKNOWN,
}


def classify_host_failure(value: Any) -> FailureClassification:
    """Map a host-integration failure onto the existing FailureClassification set.

    Accepts :class:`HostFailureKind`, :class:`FailureClassification`
    (passthrough), :class:`HostIntegrationError`, :class:`HostErrorCode`,
    or a string label. Unrecognized input maps to ``UNKNOWN`` (which the
    policy resolves to ``FAIL_CLOSED``) — this function never raises and
    never retries anything itself.
    """
    if isinstance(value, FailureClassification):
        return value
    if isinstance(value, HostFailureKind):
        return HOST_FAILURE_TO_CLASSIFICATION[value]
    if isinstance(value, HostIntegrationError):
        return HOST_ERROR_CODE_TO_CLASSIFICATION.get(
            value.code, FailureClassification.UNKNOWN
        )
    if isinstance(value, HostErrorCode):
        return HOST_ERROR_CODE_TO_CLASSIFICATION.get(
            value, FailureClassification.UNKNOWN
        )
    if isinstance(value, str):
        hit = _HOST_ALIAS_MAP.get(_normalize_label(value))
        if hit is not None:
            return hit
        return classify_or_unknown(value)
    return FailureClassification.UNKNOWN


def max_attempts_for(host_failure: Any) -> int:
    """Return the inherited bounded attempt budget for *host_failure*.

    Pure read of the existing policy table; grants nothing and runs nothing.
    The fail-closed trio always yields 0.
    """
    return decide(classify_host_failure(host_failure)).max_attempts


def is_retryable(host_failure: Any) -> bool:
    """Return whether *host_failure* may consume a retry-like attempt.

    The fail-closed trio (and UNKNOWN) always returns False.
    """
    return decide(classify_host_failure(host_failure)).retryable


@dataclass(frozen=True)
class RecoveryBridgeRecord:
    """DATA-only note of one bridge step. Permits nothing."""

    event: str
    session_id: str
    from_state: str
    to_state: str
    detail: str = ""
    at: int = 0


@dataclass(frozen=True)
class RecoveryBridgeResult:
    """Immutable outcome of one bridge recovery run."""

    session: SubagentSession
    report: RecoveryReport
    records: tuple[RecoveryBridgeRecord, ...] = ()
    ok: bool = False
    resumed: bool = False
    reason: str = ""


def _record(
    event: str,
    session_id: str,
    from_state: SubagentLifecycle,
    to_state: SubagentLifecycle,
    *,
    detail: str = "",
    now: int = 0,
) -> RecoveryBridgeRecord:
    return RecoveryBridgeRecord(
        event=event,
        session_id=session_id,
        from_state=from_state.value,
        to_state=to_state.value,
        detail=str(detail),
        at=int(now),
    )


def recover_host_session(
    session: SubagentSession,
    *,
    host_failure: Any,
    executor: Callable[[RecoveryAction, dict[str, Any]], bool] | None = None,
    now: int = 0,
    context: Mapping[str, Any] | None = None,
    audit_id: str | None = None,
) -> RecoveryBridgeResult:
    """Bridge a host-integration failure into the existing RecoveryManager.

    Steps: classify *host_failure* -> reuse ``decide`` for the bounded budget
    -> step the session (``FAILED`` / ``UNAVAILABLE``) to ``RECOVERING`` ->
    run ``RecoveryManager.recover`` within its fixed budget -> map the
    outcome back to coordination state (``RECOVERED`` -> ``READY`` resume /
    ``QUARANTINED`` -> quarantined / ``FAILED_CLOSED`` / ``BUDGET_EXHAUSTED``
    -> ``FAILED``).

    Fail-closed throughout: cross-audit input raises, non-recoverable states
    raise, the fail-closed trio never touches the executor (zero attempts via
    the existing manager), and attempts never exceed ``MAX_RECOVERY_ATTEMPTS``.

    No policy / finding / evidence mutation and no privilege change: those
    objects are not accepted, the context snapshot is copied read-only, and
    the input session is never mutated in place.
    """
    if not isinstance(session, SubagentSession):
        raise HostIntegrationError(
            HostErrorCode.INVALID, "recover_host_session requires a SubagentSession"
        )
    if audit_id is not None and audit_id != session.audit_id:
        raise HostIntegrationError(
            HostErrorCode.CROSS_AUDIT,
            "bridge cross-audit recovery rejected",
            reason=f"session audit {session.audit_id!r} != {audit_id!r}",
            quarantine=True,
        )
    if session.state not in RECOVERABLE_STATES:
        raise HostIntegrationError(
            HostErrorCode.INVALID,
            f"bridge recover requires FAILED or UNAVAILABLE, got {session.state.value}",
        )

    classification = classify_host_failure(host_failure)
    decision = decide(classification)  # reuse existing policy; no mutation
    snapshot = dict(context) if context is not None else {}

    recovering = session.transition(SubagentLifecycle.RECOVERING)
    entered = _record(
        "bridge-recovering",
        session.session_id,
        session.state,
        recovering.state,
        detail=f"host_failure={host_failure!r} classification={classification.value}",
        now=now,
    )

    manager = RecoveryManager(executor=executor) if executor is not None else RecoveryManager()
    report = manager.recover(
        RecoveryRequest(
            audit_id=session.audit_id, failure=classification, context=snapshot
        )
    )
    if report.attempts_made > MAX_BRIDGE_ATTEMPTS:  # pragma: no cover - defensive
        raise HostIntegrationError(
            HostErrorCode.INVALID, "bridge recovery exceeded attempt budget"
        )
    if report.attempts_made > decision.max_attempts:  # pragma: no cover - defensive
        raise HostIntegrationError(
            HostErrorCode.INVALID, "bridge recovery exceeded policy budget"
        )

    if report.outcome == OUTCOME_RECOVERED:
        nxt = recovering.transition(SubagentLifecycle.READY)
        event = "bridge-resumed-ready"
        ok, resumed = True, True
    elif report.outcome == OUTCOME_QUARANTINED:
        nxt = recovering.quarantine()
        event = "bridge-quarantined"
        ok, resumed = False, False
    else:  # FAILED_CLOSED / BUDGET_EXHAUSTED (or unknown -> fail closed)
        nxt = recovering.transition(SubagentLifecycle.FAILED)
        event = "bridge-failed-closed"
        ok, resumed = False, False
    detail = (
        f"outcome={report.outcome} action={report.action} "
        f"classification={classification.value} attempts={report.attempts_made}"
    )
    rec = _record(event, session.session_id, recovering.state, nxt.state, detail=detail, now=now)
    return RecoveryBridgeResult(
        session=nxt,
        report=report,
        records=(entered, rec),
        ok=ok,
        resumed=resumed,
        reason=detail,
    )


__all__ = [
    "FAIL_CLOSED_CLASSIFICATIONS",
    "HOST_ERROR_CODE_TO_CLASSIFICATION",
    "HOST_FAILURE_TO_CLASSIFICATION",
    "MAX_BRIDGE_ATTEMPTS",
    "RECOVERABLE_STATES",
    "HostFailureKind",
    "RecoveryBridgeRecord",
    "RecoveryBridgeResult",
    "classify_host_failure",
    "is_retryable",
    "max_attempts_for",
    "recover_host_session",
]
