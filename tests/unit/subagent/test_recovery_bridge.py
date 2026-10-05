"""Recovery bridge tests — POST-T018 (Agent 6C scope only)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.recovery import MAX_RECOVERY_ATTEMPTS, FailureClassification
from emo_cyber_agent.subagent.recovery_bridge import (
    FAIL_CLOSED_CLASSIFICATIONS,
    HOST_FAILURE_TO_CLASSIFICATION,
    MAX_BRIDGE_ATTEMPTS,
    HostFailureKind,
    classify_host_failure,
    is_retryable,
    max_attempts_for,
    recover_host_session,
)
from emo_cyber_agent.subagent.session import SubagentLifecycle, SubagentSession
from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

AUDIT = "audit-001"
HOST = "host-alpha"


def _session(**over) -> SubagentSession:
    base = dict(
        session_id="sess-01",
        host_id=HOST,
        audit_id=AUDIT,
        project_id="project-001",
        snapshot_id="snap-001",
        created=100,
        expires=9999,
    )
    base.update(over)
    return SubagentSession(**base)


def _failed(**over) -> SubagentSession:
    sess = _session(**over)
    sess = sess.transition(SubagentLifecycle.READY)
    sess = sess.transition(SubagentLifecycle.RUNNING)
    return sess.transition(SubagentLifecycle.FAILED)


# --- each host-failure class mapping --- #


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (HostFailureKind.TRANSPORT, FailureClassification.TRANSIENT),
        (HostFailureKind.TIMEOUT, FailureClassification.TRANSIENT),
        (HostFailureKind.MALFORMED, FailureClassification.MALFORMED_OUTPUT),
        (HostFailureKind.SESSION_STALE, FailureClassification.STALE_CONTEXT),
        (HostFailureKind.TOOL_UNAVAILABLE, FailureClassification.PROVIDER_UNAVAILABLE),
        (HostFailureKind.HOST_SCOPE_MISMATCH, FailureClassification.SCOPE_MISMATCH),
        (HostFailureKind.POLICY_DENIED, FailureClassification.POLICY_DENIED),
        (HostFailureKind.INTEGRITY_FAILURE, FailureClassification.INTEGRITY_FAILURE),
        (HostFailureKind.SCOPE_MISMATCH, FailureClassification.SCOPE_MISMATCH),
    ],
)
def test_each_host_failure_class_mapping(kind, expected):
    assert classify_host_failure(kind) == expected
    assert HOST_FAILURE_TO_CLASSIFICATION[kind] == expected
    # String labels (incl. underscore/upper variants) resolve identically.
    assert classify_host_failure(kind.value) == expected
    assert classify_host_failure(kind.value.upper().replace("-", "_")) == expected


def test_host_error_and_unknown_mapping_fail_closed():
    assert classify_host_failure(HostErrorCode.SESSION_MISMATCH) == FailureClassification.SCOPE_MISMATCH
    assert classify_host_failure(HostErrorCode.CAPABILITY_DENIED) == FailureClassification.POLICY_DENIED
    assert classify_host_failure(HostErrorCode.COMPAT_INCOMPATIBLE) == FailureClassification.INTEGRITY_FAILURE
    assert classify_host_failure(HostErrorCode.EXPIRED) == FailureClassification.STALE_CONTEXT
    err = HostIntegrationError(HostErrorCode.BINDING_MISMATCH, "mismatch", quarantine=True)
    assert classify_host_failure(err) == FailureClassification.SCOPE_MISMATCH
    # Unknown / garbage input fails closed via UNKNOWN, never raises.
    assert classify_host_failure("not-a-real-failure") == FailureClassification.UNKNOWN
    assert classify_host_failure(object()) == FailureClassification.UNKNOWN
    # Classification passthrough.
    assert classify_host_failure(FailureClassification.TRANSIENT) == FailureClassification.TRANSIENT


# --- fail-closed trio: never retry, zero attempts, executor untouched --- #


@pytest.mark.parametrize(
    "kind",
    [HostFailureKind.POLICY_DENIED, HostFailureKind.INTEGRITY_FAILURE, HostFailureKind.SCOPE_MISMATCH],
)
def test_fail_closed_trio_never_retries(kind):
    classification = classify_host_failure(kind)
    assert classification in FAIL_CLOSED_CLASSIFICATIONS
    assert is_retryable(kind) is False
    assert max_attempts_for(kind) == 0

    calls: list = []

    def _executor(action, ctx):
        calls.append(action)
        return True  # even success must not matter: terminal actions run zero attempts

    res = recover_host_session(_failed(), host_failure=kind, executor=_executor, now=10)
    assert calls == []
    assert res.report.attempts_made == 0
    assert res.ok is False and res.resumed is False
    if classification == FailureClassification.SCOPE_MISMATCH:
        assert res.report.outcome == "QUARANTINED"
        assert res.session.state == SubagentLifecycle.QUARANTINED
    else:
        assert res.report.outcome == "FAILED_CLOSED"
        assert res.session.state == SubagentLifecycle.FAILED


# --- bounded attempts inherited --- #


def test_bounded_attempts_inherited_from_policy():
    assert MAX_BRIDGE_ATTEMPTS == MAX_RECOVERY_ATTEMPTS
    calls: list = []

    def _failing(action, ctx):
        calls.append(action)
        return False

    res = recover_host_session(_failed(), host_failure=HostFailureKind.TRANSPORT, executor=_failing, now=11)
    assert res.report.outcome == "BUDGET_EXHAUSTED"
    assert res.report.attempts_made == MAX_RECOVERY_ATTEMPTS
    assert len(calls) == MAX_RECOVERY_ATTEMPTS
    assert res.session.state == SubagentLifecycle.FAILED
    assert res.ok is False


def test_per_class_budgets_match_policy_table():
    assert max_attempts_for(HostFailureKind.TRANSPORT) == 3
    assert max_attempts_for(HostFailureKind.MALFORMED) == 2
    assert max_attempts_for(HostFailureKind.SESSION_STALE) == 1
    assert max_attempts_for(HostFailureKind.TOOL_UNAVAILABLE) == 2
    assert max_attempts_for(HostFailureKind.HOST_SCOPE_MISMATCH) == 0
    assert is_retryable(HostFailureKind.TRANSPORT) is True
    assert is_retryable(HostFailureKind.HOST_SCOPE_MISMATCH) is False


# --- resume / fail outcome mapping to session transitions --- #


@pytest.mark.parametrize(
    "kind",
    [
        HostFailureKind.TRANSPORT,
        HostFailureKind.TIMEOUT,
        HostFailureKind.MALFORMED,
        HostFailureKind.SESSION_STALE,
        HostFailureKind.TOOL_UNAVAILABLE,
    ],
)
def test_retryable_resume_mapping(kind):
    res = recover_host_session(
        _failed(), host_failure=kind, executor=lambda a, c: True, now=12
    )
    assert res.report.outcome == "RECOVERED"
    assert res.ok is True and res.resumed is True
    assert res.session.state == SubagentLifecycle.READY  # resume: RECOVERING -> READY
    assert [r.event for r in res.records] == ["bridge-recovering", "bridge-resumed-ready"]


def test_malformed_maps_to_revalidate_action():
    res = recover_host_session(
        _failed(), host_failure=HostFailureKind.MALFORMED, executor=lambda a, c: True, now=13
    )
    assert res.report.action == "REVALIDATE"
    assert res.report.classification == "MALFORMED_OUTPUT"
    assert res.session.state == SubagentLifecycle.READY


def test_budget_exhausted_maps_to_failed():
    res = recover_host_session(
        _failed(), host_failure=HostFailureKind.TIMEOUT, executor=lambda a, c: False, now=14
    )
    assert res.report.outcome == "BUDGET_EXHAUSTED"
    assert res.session.state == SubagentLifecycle.FAILED
    assert res.records[-1].event == "bridge-failed-closed"


def test_host_scope_mismatch_maps_to_quarantine():
    res = recover_host_session(
        _failed(), host_failure=HostFailureKind.HOST_SCOPE_MISMATCH, executor=lambda a, c: True, now=15
    )
    assert res.report.outcome == "QUARANTINED"
    assert res.session.state == SubagentLifecycle.QUARANTINED
    assert res.records[-1].event == "bridge-quarantined"


def test_unavailable_entry_point_recovers():
    sess = _session()
    sess = sess.transition(SubagentLifecycle.UNAVAILABLE)
    res = recover_host_session(sess, host_failure="transport", executor=lambda a, c: True, now=16)
    assert res.session.state == SubagentLifecycle.READY
    assert res.ok is True


# --- no mutation, no privilege change, fail-closed guards --- #


def test_input_session_and_context_not_mutated():
    before = _failed()
    ctx = {"k": "v"}
    res = recover_host_session(before, host_failure="timeout", executor=lambda a, c: True, now=17, context=ctx)
    assert before.state == SubagentLifecycle.FAILED  # input untouched
    assert ctx == {"k": "v"}
    assert res.session is not before


def test_non_recoverable_state_and_cross_audit_rejected():
    running = _session().transition(SubagentLifecycle.READY).transition(SubagentLifecycle.RUNNING)
    with pytest.raises(HostIntegrationError):
        recover_host_session(running, host_failure="timeout", now=18)
    with pytest.raises(HostIntegrationError):
        recover_host_session(_failed(), host_failure="timeout", now=18, audit_id="audit-other")
