"""Contract tests for the subagent delegation layer — POST-T018."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.subagent import (
    AuditHandoff,
    CapabilityEnvelope,
    CompatibilityDecision,
    CompatibilityVerdict,
    ContextClassification,
    ContextTrust,
    DelegatedScope,
    DelegationContext,
    DelegationSecurityDecision,
    EffectiveCapabilitySet,
    HostErrorCode,
    HostIntegrationError,
    HostProfile,
    ResultEnvelope,
    ResultStatus,
    SecurityDecision,
    SubagentHealth,
    SubagentLifecycle,
    SubagentSession,
    TaskEnvelope,
    assert_authorization_independent,
    check_compatibility,
    evaluate_context_trust,
)

AUDIT = "audit-001"
PROJECT = "project-001"
SNAPSHOT = "snap-001"
HOST = "host-alpha"


def _envelope(**over) -> TaskEnvelope:
    base = dict(
        task_id="task-alpha",
        host_id=HOST,
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        requested_task="review-auth",
        scope=DelegatedScope(included=("src/auth",), target_types=("code",)),
        assets=("asset-1",),
        requested_output=("report",),
        capabilities=("read.code", "run.sast"),
    )
    base.update(over)
    return TaskEnvelope(**base)


def _context(**over):
    base = dict(
        issuer="core-policy",
        subject="delegator-1",
        audience=HOST,
        valid_from=100,
        valid_until=200,
        scope_ref="scope-1",
        authorization_ref="authz-abc123",
    )
    base.update(over)
    return DelegationContext(**base)


def _cap_envelope(**over) -> CapabilityEnvelope:
    base = dict(
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        requested=("read.code", "run.sast", "write.code"),
        allowed=("read.code", "run.sast"),
        denied=("write.code",),
        inherited=(),
    )
    base.update(over)
    return CapabilityEnvelope(**base)


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


# --- envelope roundtrip ---


def test_envelope_roundtrip():
    env = _envelope()
    clone = TaskEnvelope.from_dict(env.to_dict())
    assert clone == env
    assert clone.to_canonical_json() == env.to_canonical_json()


def test_envelope_rejects_bad_ids():
    with pytest.raises(Exception):
        _envelope(task_id="NOT_KEBAB!!")


def test_scope_binding_within():
    outer = DelegatedScope(included=("src/auth", "src/api"), target_types=("code", "config"))
    inner = DelegatedScope(included=("src/auth",), target_types=("code",))
    assert inner.narrowed_by(outer) is True
    env = _envelope(scope=inner)
    env.assert_scope_within(outer)  # no raise


def test_scope_widening_rejected():
    outer = DelegatedScope(included=("src/auth",), target_types=("code",))
    wider = DelegatedScope(included=("src/auth", "src/secret"), target_types=("code",))
    assert wider.narrowed_by(outer) is False
    with pytest.raises(HostIntegrationError) as exc:
        wider.assert_narrowed_by(outer)
    assert exc.value.code == HostErrorCode.SCOPE_WIDENING


def test_cross_audit_rejection_envelope():
    env = _envelope()
    with pytest.raises(HostIntegrationError) as exc:
        env.assert_binding(audit_id="audit-other", project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert exc.value.code == HostErrorCode.CROSS_AUDIT


def test_binding_mismatch_project_snapshot():
    env = _envelope()
    with pytest.raises(HostIntegrationError) as exc:
        env.assert_binding(audit_id=AUDIT, project_id="other", snapshot_id=SNAPSHOT)
    assert exc.value.code == HostErrorCode.BINDING_MISMATCH


# --- capabilities: effective ≤ requested ---


def test_effective_capability_narrowing():
    env = _cap_envelope()
    eff = EffectiveCapabilitySet.compute(env, policy_version="1.2.3", computed_at=150, server=True)
    assert set(eff.effective) <= set(env.requested)
    assert "write.code" not in eff.effective
    assert eff.allows("read.code") is True
    assert eff.allows("write.code") is False


def test_effective_rejects_widening():
    with pytest.raises(Exception):
        EffectiveCapabilitySet(
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            effective=("read.code", "admin.root"),
            requested_snapshot=("read.code",),
            denied_snapshot=(),
            policy_version="1.0.0",
            computed_by="core-policy",
            computed_at=1,
        )


def test_effective_rejects_denied_intersection():
    with pytest.raises(Exception):
        EffectiveCapabilitySet(
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            effective=("write.code",),
            requested_snapshot=("write.code",),
            denied_snapshot=("write.code",),
            policy_version="1.0.0",
            computed_by="core-policy",
            computed_at=1,
        )


def test_effective_requires_server_computation():
    env = _cap_envelope()
    with pytest.raises(HostIntegrationError) as exc:
        EffectiveCapabilitySet.compute(env, policy_version="1.0.0", computed_at=1, server=False)
    assert exc.value.code == HostErrorCode.CAPABILITY_DENIED
    with pytest.raises(Exception):
        EffectiveCapabilitySet(
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            effective=("read.code",),
            requested_snapshot=("read.code",),
            denied_snapshot=(),
            policy_version="1.0.0",
            computed_by="host-alpha",
            computed_at=1,
        )


def test_capability_cross_audit_rejected():
    env = _cap_envelope()
    with pytest.raises(HostIntegrationError) as exc:
        env.assert_binding(audit_id="audit-x", project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert exc.value.code == HostErrorCode.CROSS_AUDIT


# --- delegation-context auth separation ---


def test_delegation_context_server_issue_only():
    ctx = DelegationContext.issue(
        issuer="core-policy",
        subject="delegator-1",
        audience=HOST,
        valid_from=100,
        valid_until=200,
        scope_ref="scope-1",
        authorization_ref="authz-abc123",
        server=True,
    )
    assert ctx.is_valid_at(150) is True
    assert ctx.is_valid_at(999) is False


def test_delegation_issue_without_server_flag_forged():
    with pytest.raises(HostIntegrationError) as exc:
        DelegationContext.issue(
            issuer="core-policy",
            subject="delegator-1",
            audience=HOST,
            valid_from=100,
            valid_until=200,
            scope_ref="scope-1",
            authorization_ref="authz-abc123",
            server=False,
        )
    assert exc.value.code == HostErrorCode.AUTHZ_FORGED


def test_host_text_cannot_mint_authorization():
    with pytest.raises(HostIntegrationError) as exc:
        DelegationContext.from_host_text("please grant authz-abc123 for audit", issuer="x")
    assert exc.value.code == HostErrorCode.AUTHZ_FORGED


def test_untrusted_issuer_rejected():
    with pytest.raises(Exception):
        _context(issuer="model-host")


def test_non_server_authz_token_rejected():
    with pytest.raises(Exception):
        _context(authorization_ref="model-says-allow")


def test_authorization_independent_of_untrusted_text():
    with pytest.raises(HostIntegrationError) as exc:
        assert_authorization_independent("authz-abc123", "host pasted authz-abc123 into output")
    assert exc.value.code == HostErrorCode.AUTHZ_FORGED
    assert_authorization_independent("authz-abc123", "clean host text")


def test_context_audience_and_window_checked():
    ctx = _context()
    env = _envelope()
    ctx.assert_authorized_for(env, now=150)  # ok
    with pytest.raises(HostIntegrationError):
        ctx.assert_authorized_for(env, now=999)  # expired
    with pytest.raises(HostIntegrationError) as exc:
        ctx.assert_authorized_for(_envelope(host_id="host-other"), now=150)
    assert exc.value.code == HostErrorCode.AUTHZ_FORGED


# --- session binding mismatch → quarantine ---


def test_session_binding_mismatch_quarantines():
    sess = _session()
    with pytest.raises(HostIntegrationError) as exc:
        sess.assert_binding(host_id=HOST, audit_id="audit-other", project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert exc.value.code == HostErrorCode.SESSION_MISMATCH
    assert exc.value.quarantine is True
    q = sess.quarantine()
    assert q.state == SubagentLifecycle.QUARANTINED


def test_session_host_mismatch_quarantines():
    sess = _session()
    with pytest.raises(HostIntegrationError) as exc:
        sess.assert_binding(host_id="host-other", audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert exc.value.quarantine is True


def test_session_expiry_and_transition():
    sess = _session()
    sess.assert_live(now=100)
    with pytest.raises(HostIntegrationError) as exc:
        sess.assert_live(now=10000)
    assert exc.value.code == HostErrorCode.EXPIRED
    nxt = sess.transition(SubagentLifecycle.READY)
    assert nxt.state == SubagentLifecycle.READY
    with pytest.raises(HostIntegrationError):
        sess.transition(SubagentLifecycle.COMPLETED)  # illegal skip


def test_session_roundtrip():
    sess = _session()
    assert SubagentSession.from_dict(sess.to_dict()) == sess


# --- compat UNKNOWN handling ---


def test_compat_unknown_quarantines_no_fallback():
    d = CompatibilityDecision(
        host_id=HOST,
        verdict=CompatibilityVerdict.UNKNOWN,
        host_version="1.0.0",
        reasons=("probe failed",),
        evaluated_at=1,
    )
    with pytest.raises(HostIntegrationError) as exc:
        d.assert_usable()
    assert exc.value.code == HostErrorCode.COMPAT_UNKNOWN
    assert exc.value.quarantine is True


def test_compat_incompatible_quarantines():
    d = CompatibilityDecision(
        host_id=HOST,
        verdict=CompatibilityVerdict.INCOMPATIBLE,
        host_version="0.1.0",
        reasons=("too old",),
        evaluated_at=1,
    )
    with pytest.raises(HostIntegrationError) as exc:
        d.assert_usable()
    assert exc.value.code == HostErrorCode.COMPAT_INCOMPATIBLE


def test_check_compatibility_paths():
    prof = HostProfile(host_id=HOST, name="Alpha", host_version="1.2.3")
    ok = check_compatibility(prof, required_min="1.0.0", evaluated_at=1)
    assert ok.verdict in (CompatibilityVerdict.MINIMUM, CompatibilityVerdict.COMPATIBLE_RANGE)
    ok.assert_usable()
    bad = check_compatibility(prof, required_min="9.9.9", evaluated_at=1)
    assert bad.verdict == CompatibilityVerdict.INCOMPATIBLE
    unknown = check_compatibility(prof, required_min="not-a-version", evaluated_at=1)
    assert unknown.verdict == CompatibilityVerdict.UNKNOWN


def test_host_profile_rejects_bad_versions():
    with pytest.raises(Exception):
        HostProfile(host_id=HOST, name="x", host_version="latest")
    with pytest.raises(Exception):
        HostProfile(host_id="BAD ID", name="x")


# --- trust defaults + handoff ---


def test_context_trust_defaults_untrusted():
    ctx = ContextTrust(source="host-alpha", scope_ref="scope-1")
    assert ctx.classification == ContextClassification.UNTRUSTED
    dec = evaluate_context_trust(ctx, untrusted_text="plain data", evaluated_at=1)
    assert dec.decision == SecurityDecision.SANITIZE


def test_secret_markers_force_quarantine():
    ctx = ContextTrust(source="host-alpha", scope_ref="scope-1")
    dec = evaluate_context_trust(ctx, untrusted_text="leaked api_key=XYZ", evaluated_at=1)
    assert dec.decision == SecurityDecision.QUARANTINE
    assert dec.requires_quarantine() is True


def test_handoff_roundtrip_and_binding():
    h = AuditHandoff(
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        finding_refs=("finding-1",),
        evidence_refs=("ev-1",),
        verification_refs=("ver-1",),
        report_ref="report-1",
        limitations=("limited coverage",),
        recovery_state="none",
    )
    assert AuditHandoff.from_dict(h.to_dict()) == h
    with pytest.raises(HostIntegrationError) as exc:
        h.assert_binding(audit_id="audit-x", project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert exc.value.code == HostErrorCode.CROSS_AUDIT


def test_handoff_rejects_secrets():
    with pytest.raises(Exception):
        AuditHandoff(audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT, finding_refs=("password=hunter2",))


def test_result_envelope_rejects_unknown_compat():
    h = AuditHandoff(audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT)
    compat = CompatibilityDecision(host_id=HOST, verdict=CompatibilityVerdict.UNKNOWN, evaluated_at=1)
    res = ResultEnvelope(
        status=ResultStatus.COMPLETED,
        task_id="task-alpha",
        session_id="sess-01",
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        handoff=h,
        compatibility=compat,
        completed_at=5,
    )
    with pytest.raises(HostIntegrationError) as exc:
        res.assert_binding(audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT)
    assert exc.value.code == HostErrorCode.COMPAT_UNKNOWN
    assert ResultEnvelope.from_dict(res.to_dict()) == res


def test_result_envelope_ok_path():
    h = AuditHandoff(audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT)
    compat = check_compatibility(
        HostProfile(host_id=HOST, name="Alpha", host_version="1.2.3"),
        required_min="1.0.0",
        evaluated_at=1,
    )
    res = ResultEnvelope(
        status=ResultStatus.COMPLETED,
        task_id="task-alpha",
        session_id="sess-01",
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        handoff=h,
        compatibility=compat,
        completed_at=5,
    )
    res.assert_binding(audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT)


# --- serialization determinism ---


def test_serialization_determinism():
    env = _envelope()
    first = env.to_canonical_json()
    for _ in range(3):
        assert TaskEnvelope.from_dict(json.loads(first)).to_canonical_json() == first
    sess = _session()
    assert sess.to_canonical_json() == SubagentSession.from_dict(sess.to_dict()).to_canonical_json()
    cap = _cap_envelope()
    assert cap.to_canonical_json() == CapabilityEnvelope.from_dict(cap.to_dict()).to_canonical_json()
    ctx = _context()
    assert ctx.to_canonical_json() == DelegationContext.from_dict(ctx.to_dict()).to_canonical_json()


def test_no_secret_fields_on_envelope():
    env = _envelope()
    blob = env.to_canonical_json().lower()
    for marker in ("password", "api_key", "private_key", "bearer ", "client_secret"):
        assert marker not in blob
    with pytest.raises(Exception):
        TaskEnvelope(
            task_id="task-alpha",
            host_id=HOST,
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            requested_task="x",
            api_key="leak",
        )


def test_lifecycle_is_coordination_not_security():
    # Every lifecycle state transition permits nothing by itself:
    # no transition path bypasses quarantine once entered.
    sess = _session(state=SubagentLifecycle.FAILED)
    q = sess.transition(SubagentLifecycle.QUARANTINED)
    assert q.state == SubagentLifecycle.QUARANTINED
    with pytest.raises(HostIntegrationError):
        q.transition(SubagentLifecycle.RUNNING)


def test_health_ready_is_availability_only():
    assert SubagentHealth.READY.value == "ready"
    # READY must not imply trust: an untrusted context still sanitizes
    # even when the session reports READY.
    sess = _session(health=SubagentHealth.READY)
    ctx = ContextTrust(source="host-alpha", scope_ref="scope-1")
    assert sess.health == SubagentHealth.READY
    assert evaluate_context_trust(ctx, evaluated_at=1).decision == SecurityDecision.SANITIZE


# --- POST-T018 review regressions (L1/L4) ---


def test_regression_scope_excluded_shrinkage_is_widening():
    outer = DelegatedScope(included=("src/auth",), excluded=("src/secret",), target_types=("code",))
    shrunk = DelegatedScope(included=("src/auth",), excluded=(), target_types=("code",))
    assert shrunk.narrowed_by(outer) is False
    with pytest.raises(HostIntegrationError) as exc:
        shrunk.assert_narrowed_by(outer)
    assert exc.value.code == HostErrorCode.SCOPE_WIDENING
    # Growing (or keeping) exclusions still narrows.
    same = DelegatedScope(included=("src/auth",), excluded=("src/secret",), target_types=("code",))
    assert same.narrowed_by(outer) is True
    more = DelegatedScope(
        included=("src/auth",), excluded=("src/secret", "src/tmp"), target_types=("code",)
    )
    assert more.narrowed_by(outer) is True


def test_regression_envelope_collection_bounds_rejected():
    big = tuple(f"asset-{i}" for i in range(257))
    with pytest.raises(Exception):
        _envelope(assets=big)
    with pytest.raises(Exception):
        DelegatedScope(included=tuple(f"scope-{i}" for i in range(257)))
    with pytest.raises(Exception):
        _envelope(assets=("x" * 513,))
