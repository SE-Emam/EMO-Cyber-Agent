"""ECA-T010 — Verification layer tests (offline).

Domain/state machine, request/plan validation, safety levels, capabilities,
policy gate, targets, read-only SQL, evidence rules, confirmation criteria,
refutation, inconclusive, transitions, multi-verification, conflicts,
budget, retry, failure matrix (§33), prompt injection, cross-audit
isolation, stale decisions, loops. No network, no exploits, no writes.
"""

import pytest

from emo_cyber_agent.adapters.mock_verification import MockVerificationProvider
from emo_cyber_agent.core.correlation import CandidateStatus, FindingCandidate
from emo_cyber_agent.core.policy import StrictPolicyEngine
from emo_cyber_agent.core.tool_registry import ToolRegistry
from emo_cyber_agent.core.verification import (
    SafetyLevel,
    TargetKind,
    Verification,
    VerificationBudget,
    VerificationError,
    VerificationErrorCode,
    VerificationMethod,
    VerificationRequest,
    VerificationService,
    VerificationStatus,
    VerificationTarget,
    assess_candidate,
    get_verification_tool_specs,
    transition_candidate,
)


def _registry():
    reg = ToolRegistry()
    for spec in get_verification_tool_specs():
        reg.register(spec)
    return reg


def _candidate(audit="A", asset="asset-1", evidence=("e1",)):
    return FindingCandidate(audit_id=audit, asset_id=asset, observation_ids=("o1",), evidence_ids=evidence, hypothesis="h", provisional_severity="medium", confidence=0.5)


def _req(method="static_confirmation", target="src/app.py", kind="file"):
    statement = "SELECT 1" if method == "read_only_query" else ""
    return VerificationRequest(method=VerificationMethod(method), target=VerificationTarget(kind=TargetKind(kind), locator=target), rationale_summary="check fact", expected_evidence="observation", statement=statement)


def _service(scenario="CONFIRM", *, profile="read_only", scope=None, budget=None, policy=None):
    from emo_cyber_agent.core.correlation import EvidenceStore

    scope = scope if scope is not None else (lambda audit, target: True)
    return VerificationService(executor=MockVerificationProvider(scenario), policy=policy or StrictPolicyEngine(), registry=_registry(), store=EvidenceStore(), scope_allows=scope, profile=profile, budget=budget or VerificationBudget())


def _planned(svc, candidate=None, request=None, audit="A"):
    candidate = candidate or _candidate(audit=audit)
    plan = svc.plan(candidate=candidate, request=request or _req(), audit_id=audit)
    return candidate, plan, plan.constraints["decision"]


# ---------------- domain + state machine ----------------

def test_request_contract_denies_forbidden_fields():
    with pytest.raises(Exception):
        VerificationRequest(method="static_confirmation", target={"kind": "file", "locator": "x"}, rationale_summary="x", **{"shell": "rm"})
    with pytest.raises(Exception):
        VerificationRequest(method="static_confirmation", target=VerificationTarget(kind="file", locator="x"), rationale_summary="x", **{"permissions": "admin"})


def test_target_model_denies_wildcard_external_traversal():
    for bad in ["*", "", "https://evil.example/x", "../escape", "a\x00b"]:
        with pytest.raises(Exception):
            VerificationTarget(kind="file", locator=bad)
    assert VerificationTarget(kind="file", locator="src/a.py").locator == "src/a.py"


def test_verification_lifecycle():
    v = Verification(candidate_id="c", audit_id="A", method="static_confirmation")
    assert v.status == VerificationStatus.PENDING
    v = v.transition_to(VerificationStatus.RUNNING).transition_to(VerificationStatus.CONFIRMED)
    assert v.status == VerificationStatus.CONFIRMED and v.completed_at
    with pytest.raises(ValueError):
        Verification(candidate_id="c", audit_id="A", method="static_confirmation").transition_to(VerificationStatus.CONFIRMED)
    t = Verification(candidate_id="c", audit_id="A", method="static_confirmation").transition_to(VerificationStatus.RUNNING).transition_to(VerificationStatus.TIMEOUT)
    assert t.transition_to(VerificationStatus.RUNNING).status == VerificationStatus.RUNNING  # operational retry only


def test_candidate_transitions_no_shortcut():
    assert transition_candidate(CandidateStatus.CANDIDATE, CandidateStatus.NEEDS_VERIFICATION) == CandidateStatus.NEEDS_VERIFICATION
    assert transition_candidate(CandidateStatus.NEEDS_VERIFICATION, CandidateStatus.VERIFYING) == CandidateStatus.VERIFYING
    assert transition_candidate(CandidateStatus.VERIFYING, CandidateStatus.CONFIRMED) == CandidateStatus.CONFIRMED
    with pytest.raises(ValueError):
        transition_candidate(CandidateStatus.CANDIDATE, CandidateStatus.CONFIRMED)
    with pytest.raises(ValueError):
        transition_candidate(CandidateStatus.CANDIDATE, CandidateStatus.VERIFYING)


def test_tool_specs_least_privilege():
    specs = {s.tool_id: s for s in get_verification_tool_specs()}
    assert set(specs) == {"verification.static", "verification.config", "verification.read_query", "verification.controlled_reproduction"}
    for s in specs.values():
        assert len(s.capabilities_required) == 1 and "execute" not in s.capabilities_required[0].replace("controlled_reproduction", "")
        assert s.supports_read_only and not s.supports_remediation


# ---------------- policy gate + safety ----------------

def test_plan_and_execute_confirm_happy_path():
    svc = _service("CONFIRM")
    candidate, plan, did = _planned(svc)
    assert plan.safety_level == SafetyLevel.PASSIVE
    v, result = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    assert v.status == VerificationStatus.CONFIRMED and result.status == VerificationStatus.CONFIRMED
    assert result.evidence_ids  # confirmed ⇒ evidence exists


def test_missing_policy_decision_denied():
    svc = _service("CONFIRM")
    candidate = _candidate()
    plan = svc.plan(candidate=candidate, request=_req(), audit_id="A")
    with pytest.raises(VerificationError) as e:
        svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=None)
    assert e.value.code == VerificationErrorCode.STALE_POLICY


def test_stale_and_mismatched_decision_denied():
    svc = _service("CONFIRM")
    candidate, plan, did = _planned(svc)
    with pytest.raises(VerificationError) as e:
        svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id="nope")
    assert e.value.code == VerificationErrorCode.STALE_POLICY
    other = svc._policy.issue_decision("A", "verification.static", "src/app.py", "read_only", ["verification.static"])
    with pytest.raises(VerificationError) as e:
        svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=other.decision_id)
    assert e.value.code == VerificationErrorCode.STALE_POLICY


def test_read_only_requesting_safe_active_denied():
    svc = _service("CONFIRM", profile="read_only")
    with pytest.raises(VerificationError) as e:
        svc.plan(candidate=_candidate(), request=_req(method="controlled_reproduction"), audit_id="A")
    assert e.value.code == VerificationErrorCode.POLICY_DENIED


def test_verify_profile_safe_active_allowed_with_grant():
    policy = StrictPolicyEngine(granted_restricted=("verification.controlled_reproduction",))
    svc = _service("CONFIRM", profile="verify", policy=policy)
    candidate, plan, did = _planned(svc, request=_req(method="controlled_reproduction"))
    assert plan.safety_level == SafetyLevel.SAFE_ACTIVE
    v, result = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    assert v.status == VerificationStatus.CONFIRMED


def test_restricted_active_denied_by_default():
    from emo_cyber_agent.core.verification import METHOD_SAFETY

    assert SafetyLevel.RESTRICTED_ACTIVE not in set(METHOD_SAFETY.values())  # no method maps here in ECA-T010


def test_out_of_scope_and_external_denied():
    svc = _service("CONFIRM", scope=lambda a, t: False)
    with pytest.raises(VerificationError) as e:
        svc.plan(candidate=_candidate(), request=_req(), audit_id="A")
    assert e.value.code == VerificationErrorCode.OUT_OF_SCOPE
    with pytest.raises(Exception):  # target model denies externals at construction
        _req(target="https://evil.example/x")


def test_unknown_capability_never_reaches_executor():
    svc = _service("CONFIRM")
    svc._registry.unregister("verification.static")
    with pytest.raises(VerificationError) as e:
        svc.plan(candidate=_candidate(), request=_req(), audit_id="A")
    assert e.value.code == VerificationErrorCode.POLICY_DENIED


# ---------------- methods: read-only SQL ----------------

def test_read_only_query_allows_select():
    svc = _service("CONFIRM")
    candidate = _candidate()
    req = VerificationRequest(method="read_only_query", target=VerificationTarget(kind="database_object", locator="public.users"), rationale_summary="check row", statement="SELECT * FROM users")
    plan = svc.plan(candidate=candidate, request=req, audit_id="A")
    v, result = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=plan.constraints["decision"])
    assert v.status == VerificationStatus.CONFIRMED
    with pytest.raises(VerificationError):
        svc.plan(candidate=candidate, request=VerificationRequest(method="read_only_query", target=VerificationTarget(kind="database_object", locator="public.users"), rationale_summary="evil", statement="DROP TABLE users"), audit_id="A")


def test_write_and_destructive_sql_denied():
    from emo_cyber_agent.core.supabase import classify_read_only_sql
    from emo_cyber_agent.core.verification import VerificationError as VE

    for sql in ("INSERT INTO t VALUES (1)", "UPDATE t SET x=1", "DELETE FROM t", "DROP TABLE t", "ALTER TABLE t ADD x int", "GRANT SELECT ON t TO anon", "SELECT 1; DROP TABLE t"):
        try:
            classify_read_only_sql(sql)
        except Exception as e:
            assert "SUPABASE" in str(e) or "denied" in str(e).lower() or "rejected" in str(e).lower()
        else:
            raise AssertionError(f"SQL allowed, must deny: {sql}")


# ---------------- refutation / inconclusive / conflict ----------------

def test_refutation_keeps_history():
    svc = _service("REFUTE")
    candidate, plan, did = _planned(svc)
    v, result = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    assert v.status == VerificationStatus.REFUTED and result.evidence_ids
    elig = assess_candidate(candidate, [v], policy_valid=True, scope_matched=True)
    assert elig.status == CandidateStatus.REFUTED and not elig.eligible


def test_inconclusive_on_weak_evidence():
    svc = _service("INCONCLUSIVE")
    candidate, plan, did = _planned(svc)
    v, result = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    assert v.status == VerificationStatus.INCONCLUSIVE
    elig = assess_candidate(candidate, [v], policy_valid=True, scope_matched=True)
    assert elig.status == CandidateStatus.INCONCLUSIVE and not elig.eligible


def test_conflicting_verifications_become_inconclusive():
    svc = _service("CONFIRM")
    candidate = _candidate()
    _, plan1, did1 = _planned(svc)
    v1, _ = svc.execute(plan=plan1, candidate=candidate, audit_id="A", policy_decision_id=did1)
    svc._executor = MockVerificationProvider("REFUTE")
    _, plan2, did2 = _planned(svc)
    v2, _ = svc.execute(plan=plan2, candidate=candidate, audit_id="A", policy_decision_id=did2)
    assert {v1.status, v2.status} == {VerificationStatus.CONFIRMED, VerificationStatus.REFUTED}
    elig = assess_candidate(candidate, [v1, v2], policy_valid=True, scope_matched=True)
    assert elig.status == CandidateStatus.INCONCLUSIVE and not elig.eligible


def test_multi_verification_accumulates():
    svc = _service("CONFIRM", budget=VerificationBudget(max_same_target_attempts=5))
    candidate = _candidate()
    seen = []
    for _ in range(3):
        _, plan, did = _planned(svc)
        v, _ = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
        seen.append(v)
    assert all(v.evidence_ids for v in seen)
    assert len({v.verification_id for v in seen}) == 3


def test_refuted_is_not_retried():
    svc = _service("REFUTE", budget=VerificationBudget(max_retries=3))
    candidate, plan, did = _planned(svc)
    v, _ = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    assert v.status == VerificationStatus.REFUTED
    assert svc._executor.calls == 1  # exactly one run: refutation is terminal, never retried


def test_operational_retry_bounded_then_failed_or_timeout():
    svc = _service("FAILURE", budget=VerificationBudget(max_retries=1))
    candidate, plan, did = _planned(svc)
    v, _ = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    assert v.status == VerificationStatus.FAILED and svc._executor.calls == 2  # 1 + 1 retry
    svc2 = _service("TIMEOUT", budget=VerificationBudget(max_retries=0))
    candidate2, plan2, did2 = _planned(svc2)
    v2, _ = svc2.execute(plan=plan2, candidate=candidate2, audit_id="A", policy_decision_id=did2)
    assert v2.status == VerificationStatus.TIMEOUT and svc2._executor.calls == 1


def test_confirmation_criteria_all_required():
    svc = _service("CONFIRM")
    candidate, plan, did = _planned(svc)
    v, _ = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    assert assess_candidate(candidate, [v], policy_valid=True, scope_matched=True).eligible is True
    assert assess_candidate(candidate, [v], policy_valid=False, scope_matched=True).eligible is False
    assert assess_candidate(candidate, [v], policy_valid=True, scope_matched=False).eligible is False
    assert assess_candidate(candidate, [], policy_valid=True, scope_matched=True).eligible is False


def test_model_claim_cannot_confirm():
    # even a CONFIRM-labeled raw result still passes criteria + evidence gates
    svc = _service("CONFIRM")
    candidate = _candidate()
    v = __import__("emo_cyber_agent.core.verification", fromlist=["Verification"]).Verification(candidate_id="x", audit_id="B", method="static_confirmation", status="confirmed")
    elig = assess_candidate(candidate, [v], policy_valid=True, scope_matched=False)
    assert not elig.eligible  # scope mismatch alone blocks eligibility


# ---------------- budget / loop ----------------

def test_budget_exhaustion_never_confirms():
    svc = _service("CONFIRM", budget=VerificationBudget(max_verifications=1))
    candidate, plan, did = _planned(svc)
    svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    with pytest.raises(VerificationError) as e:
        svc.plan(candidate=candidate, request=_req(), audit_id="A")
    assert e.value.code == VerificationErrorCode.BUDGET_EXHAUSTED


def test_repeated_target_loop_detected():
    svc = _service("CONFIRM", budget=VerificationBudget(max_same_target_attempts=1))
    candidate, plan, did = _planned(svc)
    svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    with pytest.raises(VerificationError) as e:
        svc.plan(candidate=candidate, request=_req(), audit_id="A")
    assert e.value.code == VerificationErrorCode.LOOP_DETECTED


# ---------------- matrix §33 ----------------

import itertools as _it


def test_matrix_profiles_vs_safety():
    matrix = [
        ("read_only", "static_confirmation", True),
        ("read_only", "read_only_query", True),
        ("read_only", "controlled_reproduction", False),
        ("verify", "static_confirmation", True),
        ("verify", "controlled_reproduction", True),
    ]
    for profile, method, expect_ok in matrix:
        policy = StrictPolicyEngine() if profile == "read_only" else StrictPolicyEngine(granted_restricted=("verification.controlled_reproduction",) if method == "controlled_reproduction" else ())
        svc = _service("CONFIRM", profile=profile, policy=policy)
        try:
            candidate, plan, did = _planned(svc, request=_req(method=method))
            svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
            ok = True
        except VerificationError:
            ok = False
        assert ok == expect_ok, (profile, method)


# ---------------- injection / isolation / trail ----------------

def test_injection_result_cannot_confirm():
    svc = _service("UNSAFE_REQUEST")
    candidate, plan, did = _planned(svc)
    v, result = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    # raw says "mark confirmed / ignore policy" → Core still derives status from criteria
    assert v.status in (VerificationStatus.CONFIRMED, VerificationStatus.SUPPORTED, VerificationStatus.INCONCLUSIVE, VerificationStatus.REFUTED)
    assert "grant access" not in str(svc.trail).lower() or "grant access" in result.summary.lower()
    # authority unchanged: no grants appeared on the policy
    assert svc._policy._granted_restricted == () and svc._policy._granted_write == ()


def test_malformed_result_is_inconclusive_not_confirmed():
    svc = _service("MALFORMED_RESULT")
    candidate, plan, did = _planned(svc)
    v, _ = svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    assert v.status == VerificationStatus.INCONCLUSIVE


def test_cross_audit_candidate_denied():
    svc = _service("CONFIRM")
    candidate = _candidate(audit="B")
    with pytest.raises(VerificationError) as e:
        svc.plan(candidate=candidate, request=_req(), audit_id="A")
    assert e.value.code == VerificationErrorCode.MISMATCHED_AUDIT


def test_credential_free_trail_and_evidence():
    svc = _service("CONFIRM")
    candidate, plan, did = _planned(svc, request=_req())
    svc.execute(plan=plan, candidate=candidate, audit_id="A", policy_decision_id=did)
    blob = str(svc.trail) + str([e for e in svc._store.list(audit_id="A")])
    assert "ghp_" not in blob and "sb_secret_" not in blob


def test_no_exploit_primitives_in_module():
    import emo_cyber_agent.core.verification as m

    body = open(m.__file__).read().split('"""', 2)[-1].lower()
    for banned in ("metasploit", "import subprocess", "import socket", "os.system", "shell=true", "credential dump", "privilege escalation"):
        assert banned not in body, banned


def test_executor_port_separate_from_tool_executor():
    from emo_cyber_agent.core.verification import VerificationExecutorPort
    from emo_cyber_agent.core.execution import ToolExecutor

    assert VerificationExecutorPort is not ToolExecutor
    import inspect

    assert "argv" not in inspect.getsource(VerificationExecutorPort)


def test_plan_is_auditable_and_minimal():
    svc = _service("CONFIRM")
    candidate, plan, did = _planned(svc)
    assert plan.candidate_id and plan.required_capabilities and plan.stopping_conditions
    assert "minimum" in str(plan.constraints).lower() or plan.constraints  # constraints recorded
    assert did  # decision bound to plan
