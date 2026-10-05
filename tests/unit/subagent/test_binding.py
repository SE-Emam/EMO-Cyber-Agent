"""Unit tests for subagent session→audit→project→snapshot binding — POST-T018."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.subagent.binding import (
    BindingAttestation,
    BindingCode,
    BindingError,
    assert_binding,
    bind,
    consume_nonce,
)
from emo_cyber_agent.subagent.session import SubagentSession
from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError, SecurityDecision

AUDIT = "audit-001"
PROJECT = "project-001"
SNAPSHOT = "snap-001"
HOST = "host-alpha"


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


# --- happy path ---


def test_bind_happy_returns_attestation():
    att = bind(_session(), audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert att.session_id == "sess-01"
    assert att.host_id == HOST
    assert (att.audit_id, att.project_id, att.snapshot_id) == (AUDIT, PROJECT, SNAPSHOT)


def test_assert_binding_happy_no_raise():
    assert_binding(_session(), audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT) is None


def test_attestation_roundtrip():
    att = bind(_session(), audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert BindingAttestation.from_dict(att.to_dict()) == att


# --- mismatch classes ---


def test_audit_mismatch_scope_mismatch_quarantine():
    with pytest.raises(BindingError) as exc:
        bind(_session(), audit_id="audit-other", project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert exc.value.binding == BindingCode.SCOPE_MISMATCH
    assert exc.value.decision == SecurityDecision.QUARANTINE
    assert exc.value.quarantine is True
    assert exc.value.requires_quarantine() is True


def test_project_mismatch_scope_mismatch_quarantine():
    with pytest.raises(BindingError) as exc:
        bind(_session(), audit_id=AUDIT, project_id="project-other", snapshot_id=SNAPSHOT)
    assert exc.value.binding == BindingCode.SCOPE_MISMATCH
    assert exc.value.quarantine is True


def test_snapshot_mismatch_is_stale_quarantine():
    with pytest.raises(BindingError) as exc:
        bind(_session(), audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-002")
    assert exc.value.binding == BindingCode.STALE_SNAPSHOT
    assert exc.value.decision == SecurityDecision.QUARANTINE
    assert exc.value.quarantine is True


def test_assert_binding_each_mismatch_class():
    sess = _session()
    with pytest.raises(BindingError) as exc:
        assert_binding(sess, audit_id="audit-x", project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert exc.value.binding == BindingCode.SCOPE_MISMATCH
    with pytest.raises(BindingError) as exc:
        assert_binding(sess, audit_id=AUDIT, project_id="project-x", snapshot_id=SNAPSHOT)
    assert exc.value.binding == BindingCode.SCOPE_MISMATCH
    with pytest.raises(BindingError) as exc:
        assert_binding(sess, audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-x")
    assert exc.value.binding == BindingCode.STALE_SNAPSHOT


def test_mismatch_is_host_integration_error():
    # Existing except-HostIntegrationError boundaries keep working.
    with pytest.raises(HostIntegrationError) as exc:
        bind(_session(), audit_id="audit-other", project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert exc.value.code == HostErrorCode.SESSION_MISMATCH
    assert exc.value.quarantine is True


def test_no_partial_use_on_mismatch():
    with pytest.raises(BindingError):
        bind(_session(), audit_id="audit-other", project_id=PROJECT, snapshot_id=SNAPSHOT)


def test_first_failure_is_deterministic_audit_first():
    sess = _session()
    with pytest.raises(BindingError) as exc:
        bind(sess, audit_id="audit-x", project_id="project-x", snapshot_id="snap-x")
    assert exc.value.binding == BindingCode.SCOPE_MISMATCH
    assert exc.value.field == "audit_id"


# --- nonce replay guard ---


def test_nonce_consume_returns_new_set_input_untouched():
    seen: frozenset[str] = frozenset()
    nxt = consume_nonce(seen, "nonce-1")
    assert "nonce-1" in nxt
    assert seen == frozenset()  # pure: input never mutated


def test_nonce_replay_denied_no_quarantine():
    seen = consume_nonce(frozenset(), "nonce-1")
    with pytest.raises(BindingError) as exc:
        consume_nonce(seen, "nonce-1")
    assert exc.value.binding == BindingCode.REPLAY_DENIED
    assert exc.value.decision == SecurityDecision.DENY
    assert exc.value.quarantine is False
    assert exc.value.requires_quarantine() is False


def test_nonce_distinct_nonces_ok():
    seen = consume_nonce(frozenset(), "nonce-1")
    seen = consume_nonce(seen, "nonce-2")
    assert seen == frozenset({"nonce-1", "nonce-2"})


def test_nonce_bad_inputs_rejected():
    with pytest.raises((TypeError, ValueError)):
        consume_nonce(frozenset(), "")
    with pytest.raises(TypeError):
        consume_nonce({"nonce-1"}, "nonce-2")  # type: ignore[arg-type]


# --- determinism ---


def test_bind_deterministic():
    sess = _session()
    kw = dict(audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT)
    first = bind(sess, **kw)
    for _ in range(3):
        assert bind(sess, **kw) == first
        assert bind(sess, **kw).to_canonical_json() == first.to_canonical_json()
    assert first.digest() == bind(sess, **kw).digest()


def test_failure_deterministic():
    for _ in range(3):
        with pytest.raises(BindingError) as exc:
            bind(_session(), audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-stale")
        assert exc.value.binding == BindingCode.STALE_SNAPSHOT


# --- type safety ---


def test_wrong_types_raise_type_error():
    with pytest.raises(TypeError):
        bind("not-a-session", audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        bind(_session(), audit_id=123, project_id=PROJECT, snapshot_id=SNAPSHOT)  # type: ignore[arg-type]
