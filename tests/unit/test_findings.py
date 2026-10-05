"""ECA-T011 — Finding lifecycle & classification tests (offline).

Lifecycle, evidence gates, classification (severity/confidence/CWE/OWASP/
CVSS/conflicts), identity/dedup, root-cause separation, remediation,
suppression, provenance, model boundary, reportability. No reporting
render, no remediation execution, no active exploitation.
"""

import pytest

from emo_cyber_agent.core.correlation import FindingCandidate
from emo_cyber_agent.core.findings import (
    Eligibility,
    FindingStatus,
    FindingStore,
    Remediation,
    SecurityFinding,
    Severity,
    SuppressionRecord,
    apply_model_suggestion,
    assess_candidate,
    classify_candidate,
    evaluate_finding_eligibility,
    finding_fingerprint,
    is_reportable,
    promote_candidate,
    regression_key,
    transition_candidate_state,
    transition_finding,
)


def _cand(rule="R1-auth-weakness@corr-v1", sev="high", audit="A", evidence=("e1", "e2")):
    # engine-born state (correlated), as produced by CorrelationEngine — never raw CANDIDATE for promotion paths
    return FindingCandidate(audit_id=audit, asset_id="asset-1", observation_ids=("o1",), evidence_ids=evidence, hypothesis="hypothesis text", provisional_severity=sev, confidence=0.6, rule_id=rule, status="correlated")


def _classify(rule="R1-auth-weakness@corr-v1", sev="high", vstatus="confirmed", scanners=None):
    c = _cand(rule=rule, sev=sev)
    return classify_candidate(candidate=c, verification_status=vstatus, scanner_severities=scanners or [], evidence_count=3, independent_sources=2, contradiction=False)


def _promote(rule="R1-auth-weakness@corr-v1", audit="A"):
    c = _cand(rule=rule, audit=audit)
    cl, _ = _classify(rule=rule)
    return promote_candidate(candidate=c, verification_status="confirmed", verification_ids=("v1",), evidence_ids=["e1", "e2"], observation_ids=["o1"], classification=cl, scope_ok=True, policy_ok=True, audit_id=audit, asset_id="asset-1", location="src/api/u.ts", identity="R1", remediation=Remediation(recommendation="enforce server-side authorization checks", affected_component="src/api/u.ts", remediation_type="authorization-check", validation_guidance="re-run RLS + handler tests"))


# ---------------- fixtures (10 mandated) ----------------

def fx_confirmed_authorization():
    return _promote()


def fx_refuted_authorization():
    return _cand(rule="R1-auth-weakness@corr-v1")


def fx_unverified_sql_injection():
    return _cand(rule="R9-sql-injection@corr-v1", sev="high")


def fx_confirmed_dependency():
    c = _cand(rule="R2-vuln-dependency@corr-v1", sev="medium")
    cl, _ = _classify(rule="R2-vuln-dependency@corr-v1", sev="medium")
    return promote_candidate(candidate=c, verification_status="confirmed", verification_ids=("v2",), evidence_ids=["e1", "e2"], observation_ids=["o2"], classification=cl, scope_ok=True, policy_ok=True, audit_id="A", asset_id="dep", location="package.json", identity="CVE-2024-1")


def fx_rls_access_risk():
    return _cand(rule="R4-access-control-risk@corr-v1", sev="medium")


def fx_secret_exposure():
    return _cand(rule="R3-secret-exposure@corr-v1", sev="high")


def fx_conflicting_classification():
    c = _cand()
    return classify_candidate(candidate=c, verification_status="supported", scanner_severities=["critical", "low"], evidence_count=3, independent_sources=2, contradiction=False)


def fx_duplicate_scanner_results():
    a = _promote()
    b = _promote()  # same inputs → same fingerprint
    return a, b


def fx_cross_audit_attempt():
    return _cand(audit="B")


def fx_model_overrule_attempt():
    return {"severity": "critical", "status": "confirmed", "evidence_ids": ("evil",), "audit_id": "X", "cwe": "CWE-000"}


# ---------------- lifecycle ----------------

def test_candidate_cannot_skip_verification():
    with pytest.raises(ValueError):
        transition_finding(FindingStatus.CANDIDATE, FindingStatus.CONFIRMED)
    with pytest.raises(ValueError):
        transition_finding(FindingStatus.CANDIDATE, FindingStatus.REPORTED)
    with pytest.raises(ValueError):
        transition_candidate_state(FindingStatus.CANDIDATE, FindingStatus.CONFIRMED)


def test_verified_confirmed_reported_resolved_chain():
    f = fx_confirmed_authorization()
    assert f.status == FindingStatus.CONFIRMED
    f = f.transition_to(FindingStatus.REPORTED).transition_to(FindingStatus.RESOLVED)
    assert f.status == FindingStatus.RESOLVED


def test_refuted_disputed_suppressed_duplicate_inconclusive():
    f = _promote().transition_to(FindingStatus.DISPUTED)
    assert f.transition_to(FindingStatus.TRIAGED).status == FindingStatus.TRIAGED
    g = _promote().transition_to(FindingStatus.REPORTED)
    sup = g.transition_to(FindingStatus.SUPPRESSED)
    assert sup.status == FindingStatus.SUPPRESSED
    assert sup.transition_to(FindingStatus.TRIAGED).status == FindingStatus.TRIAGED
    h = _promote()
    assert h.transition_to(FindingStatus.DISPUTED).transition_to(FindingStatus.INCONCLUSIVE).status == FindingStatus.INCONCLUSIVE


def test_resolved_vs_refuted_distinct():
    assert FindingStatus.RESOLVED != FindingStatus.REFUTED
    f = _promote().transition_to(FindingStatus.REPORTED).transition_to(FindingStatus.RESOLVED)
    assert f.status == FindingStatus.RESOLVED  # was real, then fixed + proven
    # refuted is terminal-claim-denied, never reachable from resolved
    with pytest.raises(ValueError):
        f.transition_to(FindingStatus.REFUTED)


# ---------------- evidence gates ----------------

def test_no_evidence_denied_everywhere():
    with pytest.raises(ValueError):
        FindingCandidate(audit_id="A", hypothesis="h", evidence_ids=())
    store = FindingStore()
    c = _cand()
    cl, _ = _classify()
    bad = dict(c=candidate_kwargs(c), evidence_ids=[])
    with pytest.raises(ValueError):
        promote_candidate(candidate=c, verification_status="confirmed", verification_ids=("v1",), evidence_ids=[], observation_ids=["o1"], classification=cl, scope_ok=True, policy_ok=True, audit_id="A")
    with pytest.raises(ValueError):
        store.add(_finding_no_evidence())


def candidate_kwargs(c):
    return {}


def _finding_no_evidence():
    return SecurityFinding(finding_id="x", audit_id="A", title="t", description="d", category="other", severity="low", confidence=0.1, candidate_id="c", evidence_ids=())


def test_invalid_cross_audit_evidence_denied():
    store = FindingStore()
    f = _promote()
    store.add(f)
    with pytest.raises(KeyError):
        store.get(f.finding_id, audit_id="B")
    foreign = fx_cross_audit_attempt()
    assert foreign.audit_id == "B"
    with pytest.raises(ValueError):
        promote_candidate(candidate=foreign, verification_status="confirmed", verification_ids=("v1",), evidence_ids=["e1"], observation_ids=["o1"], classification=_classify()[0], scope_ok=False, policy_ok=True, audit_id="A")


def test_missing_provenance_not_eligible():
    c = _cand()
    r = evaluate_finding_eligibility(candidate=c, evidence_ids=["e1"], provenance_ok=False, scope_ok=True, verification_status="confirmed", contradiction_unresolved=False, candidate_status="correlated", policy_ok=True)
    assert r.verdict == Eligibility.NOT_ELIGIBLE


def test_eligibility_matrix():
    c = _cand()
    ok = evaluate_finding_eligibility(candidate=c, evidence_ids=["e1", "e2"], provenance_ok=True, scope_ok=True, verification_status="confirmed", contradiction_unresolved=False, candidate_status="correlated", policy_ok=True)
    assert ok.verdict == Eligibility.ELIGIBLE
    review = evaluate_finding_eligibility(candidate=c, evidence_ids=["e1"], provenance_ok=True, scope_ok=True, verification_status="supported", contradiction_unresolved=False, candidate_status="correlated", policy_ok=True)
    assert review.verdict in (Eligibility.ELIGIBLE, Eligibility.NEEDS_REVIEW)
    bad = evaluate_finding_eligibility(candidate=c, evidence_ids=["e1"], provenance_ok=True, scope_ok=True, verification_status="confirmed", contradiction_unresolved=True, candidate_status="correlated", policy_ok=True)
    assert bad.verdict == Eligibility.NOT_ELIGIBLE


# ---------------- classification ----------------

def test_severity_confidence_independent():
    cl, _ = _classify(sev="high")
    assert cl.severity.severity == Severity.HIGH
    assert cl.confidence.value != 1.0  # confidence from evidence math, not severity
    cl2, _ = classify_candidate(candidate=_cand(sev="medium"), verification_status="confirmed", scanner_severities=[], evidence_count=1, independent_sources=1, contradiction=False)
    assert cl2.severity.severity == Severity.MEDIUM and cl2.confidence.value <= 0.95


def test_valid_and_missing_cwe():
    cl, _ = _classify(rule="R1-auth-weakness@corr-v1")
    assert cl.cwe == "CWE-639"
    cl2, _ = _classify(rule="R9-unknown@corr-v1")
    assert cl2.cwe is None  # unknown → null, never invented


def test_owasp_mapping_not_proof():
    cl, _ = _classify(rule="R1-auth-weakness@corr-v1")
    assert cl.owasp is not None and "Access Control" in cl.owasp
    cl2, _ = _classify(rule="R9-unknown@corr-v1")
    assert cl2.owasp is None


def test_cvss_passthrough_never_computed():
    cl, _ = _classify()
    assert cl.cvss_score is None and cl.cvss_source is None
    c = _cand()
    cl2, _ = classify_candidate(candidate=c, verification_status="confirmed", scanner_severities=[], evidence_count=2, independent_sources=1, contradiction=False, cvss={"vector": "CVSS:3.1/AV:N", "score": 9.1, "source": "trivy-db"})
    assert cl2.cvss_score == 9.1 and cl2.cvss_source == "trivy-db" and cl2.severity.severity == Severity.HIGH  # CVSS did not move final severity


def test_downgrade_with_reason_and_conflict():
    c = _cand(sev="high")
    cl, conflict = classify_candidate(candidate=c, verification_status="supported", scanner_severities=["low"], evidence_count=2, independent_sources=1, contradiction=False)
    assert cl.severity.severity == Severity.MEDIUM and "downgraded" in cl.severity.basis
    cl2, conflict2 = fx_conflicting_classification()
    assert conflict2 is not None and cl2.severity.severity == Severity.HIGH  # provisional kept, conflict recorded


def test_classification_explained():
    cl, _ = _classify()
    assert cl.explained and cl.severity.basis and cl.severity.source and cl.severity.rule_version == "cls-v1"


# ---------------- identity / dedup ----------------

def test_fingerprint_stable_and_scoped():
    fp1 = finding_fingerprint(audit_id="A", asset_id="a", category="authorization", location="f.py", identity="R1", rule="r")
    fp2 = finding_fingerprint(audit_id="A", asset_id="a", category="authorization", location="f.py", identity="R1", rule="r")
    fp3 = finding_fingerprint(audit_id="B", asset_id="a", category="authorization", location="f.py", identity="R1", rule="r")
    assert fp1 == fp2 and fp1 != fp3


def test_same_finding_deduplicates_locations_split():
    a, b = fx_duplicate_scanner_results()
    assert a.fingerprint == b.fingerprint
    store = FindingStore()
    canonical = store.add(a)
    back = store.add(SecurityFinding(**{**b.model_dump(), "finding_id": "other-id"}))
    assert back.finding_id == canonical.finding_id
    dup = store.get("other-id", audit_id="A")
    assert dup.status == FindingStatus.DUPLICATE and dup.provenance["duplicate_of"] == canonical.finding_id


def test_different_audits_never_merge():
    store = FindingStore()
    fa = _promote(audit="A")
    fb = _promote(audit="B")
    assert fa.fingerprint != fb.fingerprint
    store.add(fa)
    assert store.add(fb).finding_id == fb.finding_id  # separate canonical, no merge


def test_regression_key_links_history_not_evidence():
    k1 = regression_key(asset_id="a", category="authorization", location="f.py", identity="R1", rule="r")
    k2 = regression_key(asset_id="a", category="authorization", location="f.py", identity="R1", rule="r")
    assert k1 == k2  # stable across audits for comparison only


# ---------------- root cause / remediation / suppression ----------------

def test_root_cause_impact_separation():
    f = _promote()
    assert f.observed_issue and f.impact == "UNASSESSED" and f.root_cause == ""  # impact never invented


def test_remediation_structured_not_executed():
    f = _promote()
    assert f.remediation is not None
    assert f.remediation.recommendation and f.remediation.validation_guidance
    import emo_cyber_agent.core.findings as m

    assert "subprocess" not in open(m.__file__).read().split('"""', 2)[-1]


def test_suppression_requires_actor_not_model():
    with pytest.raises(ValueError):
        SuppressionRecord(reason="x", actor="model")
    with pytest.raises(ValueError):
        SuppressionRecord(reason="x", actor="LLM")
    rec = SuppressionRecord(reason="accepted risk", actor="security-team", scope="audit-A", expires_at="2027-01-01")
    assert rec.actor == "security-team"


# ---------------- provenance / reportability / snapshot ----------------

def test_provenance_chain_complete():
    f = _promote()
    for k in ("candidate", "rule", "classification_version", "finding_schema", "policy"):
        assert k in f.provenance
    assert f.verification_ids == ("v1",) and f.observation_ids == ("o1",) and f.candidate_id


def test_reportability_contract():
    ok, problems = is_reportable(_promote())
    assert ok and problems == []
    bad, problems = is_reportable(SecurityFinding(**{**_promote().model_dump(), "status": FindingStatus.CANDIDATE}))
    assert not bad and "unverified-candidate" in problems
    nofp = SecurityFinding(**{**_promote().model_dump(), "fingerprint": ""})
    assert not is_reportable(nofp)[0]


def test_finding_snapshot_versions():
    f = _promote()
    assert f.provenance["classification_version"] == "cls-v1" and f.provenance["finding_schema"] == "0.1.0"


# ---------------- model boundary ----------------

def test_model_cannot_confirm_suppress_or_change_severity():
    f = _promote()
    for attempt in (fx_model_overrule_attempt(), {"status": "suppressed"}, {"severity": "low"}, {"audit_id": "X"}, {"fingerprint": "x"}):
        with pytest.raises(ValueError):
            apply_model_suggestion(f, attempt)


def test_model_cannot_attach_foreign_evidence_or_override_taxonomy():
    f = _promote()
    with pytest.raises(ValueError):
        apply_model_suggestion(f, {"evidence_ids": ("foreign",)})
    with pytest.raises(ValueError):
        apply_model_suggestion(f, {"cwe": "CWE-000"})  # Core CWE locked
    ok = apply_model_suggestion(f, {"title": "clearer title"})
    assert ok.title == "clearer title" and ok.provenance["model_suggestion"] == "unverified" and ok.severity == f.severity


def test_model_suggestion_unverified_until_core():
    f = _promote()
    assert "model_suggestion" not in f.provenance
    g = apply_model_suggestion(f, {"description": "analyst note"})
    assert g.provenance["model_suggestion"] == "unverified"
