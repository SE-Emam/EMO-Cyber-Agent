"""Lifecycle coordinator tests — POST-T018 (Agent 6A scope only)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.recovery import MAX_RECOVERY_ATTEMPTS
from emo_cyber_agent.subagent.envelope import DelegatedScope
from emo_cyber_agent.subagent.handoff import AuditHandoff
from emo_cyber_agent.subagent.lifecycle import LifecycleCoordinator
from emo_cyber_agent.subagent.session import SubagentLifecycle, SubagentSession
from emo_cyber_agent.subagent.trust import HostIntegrationError

AUDIT = "audit-001"
PROJECT = "project-001"
SNAPSHOT = "snap-001"
HOST = "host-alpha"

SCOPE = DelegatedScope(included=("src/auth",), target_types=("code",))


def _session(**over) -> SubagentSession:
    base = dict(
        session_id="sess-01",
        host_id=HOST,
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        created=100,
        expires=9999,
    )
    base.update(over)
    return SubagentSession(**base)


def _to(session: SubagentSession, *states: SubagentLifecycle) -> SubagentSession:
    for s in states:
        session = session.transition(s)
    return session


def _handoff(*, verifications: tuple[str, ...] = ()) -> AuditHandoff:
    return AuditHandoff(
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        verification_refs=verifications,
    )


# --- start/ready --- #


def test_start_ready_binds_scope_and_delegation():
    coord = LifecycleCoordinator()
    sess = _session()
    res = coord.start(sess, scope=SCOPE, delegation_id="del-1", now=100)
    assert res.ok is True
    assert res.session.state == SubagentLifecycle.READY
    assert len(res.records) == 1
    rec = res.records[0]
    assert rec.from_state == "starting" and rec.to_state == "ready"
    assert "del-1" in rec.detail
    assert "src/auth" in rec.detail  # scope bound into the record
    # Deterministic: same inputs, same outputs.
    again = coord.start(_session(), scope=SCOPE, delegation_id="del-1", now=100)
    assert again.session == res.session
    assert again.records == res.records


def test_start_rejects_non_starting_and_expired():
    coord = LifecycleCoordinator()
    ready = _to(_session(), SubagentLifecycle.READY)
    with pytest.raises(HostIntegrationError):
        coord.start(ready, scope=SCOPE, delegation_id="del-1", now=100)
    with pytest.raises(Exception):
        coord.start(_session(), scope=SCOPE, delegation_id="del-1", now=10000)  # expired
    with pytest.raises(HostIntegrationError):
        coord.start(_session(), scope=SCOPE, delegation_id="  ", now=100)  # empty delegation


# --- timeout fail --- #


def test_timeout_running_goes_failed():
    coord = LifecycleCoordinator()
    running = _to(_session(), SubagentLifecycle.READY, SubagentLifecycle.RUNNING)
    res = coord.heartbeat(running, now=500, deadline=200)
    assert res.session.state == SubagentLifecycle.FAILED
    assert any(r.to_state == "failed" for r in res.records)


def test_heartbeat_within_deadline_is_noop():
    coord = LifecycleCoordinator()
    running = _to(_session(), SubagentLifecycle.READY, SubagentLifecycle.RUNNING)
    res = coord.heartbeat(running, now=100, deadline=200)
    assert res.session == running
    assert res.ok is True


# --- cancel terminal --- #


def test_cancel_running_terminal_never_completed():
    coord = LifecycleCoordinator()
    running = _to(_session(), SubagentLifecycle.READY, SubagentLifecycle.RUNNING)
    res = coord.cancel(running, now=150, reason="operator stop")
    assert res.session.state == SubagentLifecycle.CANCELLED
    assert res.session.terminal is True
    assert res.session.state != SubagentLifecycle.COMPLETED
    # Terminal stability: further cancel is a no-op preserving CANCELLED.
    again = coord.cancel(res.session, now=151)
    assert again.session.state == SubagentLifecycle.CANCELLED
    assert again.ok is False


def test_cancel_from_reporting_refused_fail_closed():
    coord = LifecycleCoordinator()
    reporting = _to(
        _session(),
        SubagentLifecycle.READY,
        SubagentLifecycle.RUNNING,
        SubagentLifecycle.VERIFYING,
        SubagentLifecycle.REPORTING,
    )
    with pytest.raises(HostIntegrationError):
        coord.cancel(reporting, now=150)


# --- recover bounded --- #


def test_recover_success_returns_ready():
    coord = LifecycleCoordinator(executor=lambda _a, _c: True)
    failed = _to(_session(), SubagentLifecycle.READY, SubagentLifecycle.RUNNING,
                 SubagentLifecycle.FAILED)
    res = coord.recover(failed, failure="TRANSIENT", now=200)
    assert res.ok is True
    assert res.session.state == SubagentLifecycle.READY
    assert "RECOVERED" in res.reason


def test_recover_bounded_fail_closed():
    calls = []

    def _fail(_action, _ctx):
        calls.append(1)
        return False

    coord = LifecycleCoordinator(executor=_fail)
    failed = _to(_session(), SubagentLifecycle.READY, SubagentLifecycle.RUNNING,
                 SubagentLifecycle.FAILED)
    res = coord.recover(failed, failure="TRANSIENT", now=200)
    assert res.ok is False
    assert res.session.state == SubagentLifecycle.FAILED  # fail-closed, no orphan
    assert len(calls) <= MAX_RECOVERY_ATTEMPTS
    assert "BUDGET_EXHAUSTED" in res.reason


def test_recover_policy_denied_zero_attempts():
    calls = []

    def _spy(_action, _ctx):
        calls.append(1)
        return True

    coord = LifecycleCoordinator(executor=_spy)
    failed = _to(_session(), SubagentLifecycle.READY, SubagentLifecycle.RUNNING,
                 SubagentLifecycle.FAILED)
    res = coord.recover(failed, failure="POLICY_DENIED", now=200)
    assert res.ok is False
    assert res.session.state == SubagentLifecycle.FAILED
    assert calls == []  # terminal policy: zero attempts
    assert "FAILED_CLOSED" in res.reason


# --- complete gate --- #


def test_complete_gated_without_verification_refs():
    coord = LifecycleCoordinator()
    reporting = _to(
        _session(),
        SubagentLifecycle.READY,
        SubagentLifecycle.RUNNING,
        SubagentLifecycle.VERIFYING,
        SubagentLifecycle.REPORTING,
    )
    res = coord.complete(reporting, handoff=_handoff(), now=300)
    assert res.ok is False
    assert res.session.state == SubagentLifecycle.REPORTING  # stays, with reason
    assert "verification" in res.reason.lower()


def test_complete_with_verification_refs():
    coord = LifecycleCoordinator()
    reporting = _to(
        _session(),
        SubagentLifecycle.READY,
        SubagentLifecycle.RUNNING,
        SubagentLifecycle.VERIFYING,
        SubagentLifecycle.REPORTING,
    )
    res = coord.complete(reporting, handoff=_handoff(verifications=("ver-1",)), now=300)
    assert res.ok is True
    assert res.session.state == SubagentLifecycle.COMPLETED


# --- no orphan --- #


def test_no_orphan_timeout_from_ready_bridges_to_failed():
    # READY has no direct FAILED edge; the guard must still land on FAILED.
    coord = LifecycleCoordinator()
    ready = _to(_session(), SubagentLifecycle.READY)
    res = coord.heartbeat(ready, now=999, deadline=100)
    assert res.session.state == SubagentLifecycle.FAILED
    assert len(res.records) >= 2  # bridge steps recorded


def test_no_orphan_terminal_timeout_preserved():
    coord = LifecycleCoordinator()
    cancelled = _to(
        _session(), SubagentLifecycle.READY, SubagentLifecycle.CANCELLED
    )
    res = coord.heartbeat(cancelled, now=999, deadline=100)
    assert res.session.state == SubagentLifecycle.CANCELLED  # preserved, never orphaned
