"""POST-RC-011 — Regression memory & comparator (offline).

Closed regression states, closed comparison results, honest
coverage, precedence (current evidence outranks history, history is
kept and labeled), deterministic staleness, and the two remaining
end-to-end workflows (C: baseline → target regression, F: layer
context stays inert untrusted memory). Zero Findings required.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from emo_cyber_agent.security_knowledge import (
    COMPARATOR_RESULTS,
    REGRESSION_STATES,
    KnowledgeComparator,
    SecurityKnowledgeService,
    compare_regression,
    evaluate_precedence,
    evaluate_staleness,
    route_property_key,
)

FIXTURES = Path("tests/fixtures/security_knowledge")
AUDIT = "audit-2026-001"
PROJECT = "payments-api"
KEY = route_property_key("/login", "auth")


def _fixtures() -> dict:
    return json.loads((FIXTURES / "regression_pairs.json").read_text())


# ---------------- closed state machine ----------------

def test_regression_states_are_closed():
    for pair in _fixtures()["pairs"]:
        assert pair["expected_state"] in REGRESSION_STATES


@pytest.mark.parametrize("pair", _fixtures()["pairs"], ids=lambda p: p["name"])
def test_regression_pair_state(pair: Any):
    record = compare_regression(
        audit_id=AUDIT, project_id=PROJECT, regression_key=KEY,
        base_snapshot_id="snap-0", target_snapshot_id="snap-1",
        before_digest=pair["before_digest"], after_digest=pair["after_digest"],
        before_present=pair["before_present"], after_present=pair["after_present"],
        comparable=pair["comparable"], coverage=pair["coverage"],
        prior_digests=tuple(pair["prior_digests"]),
    )
    assert record.state == pair["expected_state"]


def test_regression_identity_is_deterministic():
    kwargs = {"audit_id": AUDIT, "project_id": PROJECT, "regression_key": KEY, "before_digest": "a", "after_digest": "b"}
    first = compare_regression(**kwargs)
    second = compare_regression(**kwargs)
    assert first.regression_id == second.regression_id and first.digest == second.digest


def test_regression_key_entered_into_digest():
    a = compare_regression(audit_id=AUDIT, project_id=PROJECT, regression_key=KEY, before_digest="a", after_digest="b")
    b = compare_regression(audit_id=AUDIT, project_id=PROJECT, regression_key="regression:route:other:auth", before_digest="a", after_digest="b")
    assert a.digest != b.digest


# ---------------- comparator ----------------

@pytest.mark.parametrize("case", _fixtures()["comparisons"], ids=lambda c: c["name"])
def test_comparator_result(case: Any):
    comparison = KnowledgeComparator().compare(case["before"], case["after"], comparable=case["comparable"], coverage=case["coverage"])
    assert comparison.result == case["expected"]
    assert comparison.result in COMPARATOR_RESULTS


def test_comparator_never_creates_findings():
    comparison = KnowledgeComparator().compare({"x": 1}, {"x": 2})
    assert not hasattr(comparison, "finding_id")
    assert set(comparison.model_dump()) <= {
        "base_key", "target_key", "result", "reason_codes", "evidence_ids", "coverage", "limitations"
    }


def test_incomplete_coverage_blocks_absence_claims():
    comparison = KnowledgeComparator().compare({"x": 1}, None, coverage="incomplete")
    assert comparison.result == "INDETERMINATE"
    assert comparison.limitations


# ---------------- precedence & staleness ----------------

def test_current_evidence_outranks_history():
    assert evaluate_precedence(historical_digest="a", current_digest="b", historical_snapshot_id="s0", current_snapshot_id="s1") == "SUPERSEDED"
    assert evaluate_precedence(historical_digest="a", current_digest="a", historical_snapshot_id="s0", current_snapshot_id="s1") == "STALE"
    assert evaluate_precedence(historical_digest="a", current_digest="b", historical_snapshot_id="s1", current_snapshot_id="s1") == "CONTRADICTED"
    assert evaluate_precedence(historical_digest="a", current_digest="a", historical_snapshot_id="s1", current_snapshot_id="s1") == "CURRENT"


def test_staleness_is_deterministic():
    assert evaluate_staleness(record_snapshot_id="s1", current_snapshot_id="s1") == "FRESH_FOR_SCOPE"
    assert evaluate_staleness(record_snapshot_id="s0", current_snapshot_id="s1") == "STALE"
    assert evaluate_staleness(record_snapshot_id="s1", current_snapshot_id="s1", versions={"core": "mismatch"}) == "INCOMPATIBLE"
    assert evaluate_staleness(record_snapshot_id="s1", current_snapshot_id="s1", versions={"core": "unknown"}) == "UNKNOWN"
    assert evaluate_staleness(record_snapshot_id="", current_snapshot_id="s1") == "UNKNOWN"
    assert evaluate_staleness(record_snapshot_id="s1", current_snapshot_id="s1", record_schema_version="1.0", current_schema_version="2.0") == "INCOMPATIBLE"


# ---------------- service integration ----------------

def test_remember_regression_persists_signal():
    service = SecurityKnowledgeService()
    regression, record = service.remember_regression(
        audit_id=AUDIT, project_id=PROJECT, regression_key=KEY,
        base_snapshot_id="snap-0", target_snapshot_id="snap-1",
        before_digest="aaa1", after_digest="bbb2",
    )
    assert regression.state == "CHANGED"
    assert record.category == "CHANGE_REGRESSION_SIGNAL"
    assert record.regression_key == KEY
    assert record.trust_level == "untrusted"
    listed = service.list_project_regressions(audit_id=AUDIT, project_id=PROJECT)
    assert [r.record_id for r in listed] == [record.record_id]


def test_regression_history_is_kept_not_deleted():
    service = SecurityKnowledgeService()
    _, first = service.remember_regression(
        audit_id=AUDIT, project_id=PROJECT, regression_key=KEY,
        base_snapshot_id="snap-0", target_snapshot_id="snap-1",
        before_digest="aaa1", after_digest="bbb2",
    )
    _, second = service.remember_regression(
        audit_id=AUDIT, project_id=PROJECT, regression_key=KEY,
        base_snapshot_id="snap-1", target_snapshot_id="snap-2",
        before_digest="bbb2", after_digest="ccc3",
    )
    keys = {r.record_id for r in service.find_by_regression_key(KEY, audit_id=AUDIT, project_id=PROJECT)}
    assert first.record_id in keys and second.record_id in keys


def test_service_compares_with_baseline():
    service = SecurityKnowledgeService()
    service.remember(
        audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-0", source_type="change_analysis",
        source_id="cs-0", category="CHANGE_REGRESSION_SIGNAL", regression_key=KEY,
        content={"statement": "transport layer enabled on the edge listener"},
    )
    service.remember(
        audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-1", source_type="change_analysis",
        source_id="cs-1", category="CHANGE_REGRESSION_SIGNAL", regression_key=KEY,
        content={"statement": "transport layer enabled on the edge listener"},
    )
    same = service.compare_with_baseline(KEY, audit_id=AUDIT, project_id=PROJECT, baseline_snapshot_id="snap-0", target_snapshot_id="snap-1")
    assert same.result == "IDENTICAL"
    service.remember(
        audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-2", source_type="change_analysis",
        source_id="cs-2", category="CHANGE_REGRESSION_SIGNAL", regression_key=KEY,
        content={"statement": "rate limit configured at the gateway"},
    )
    changed = service.compare_with_baseline(KEY, audit_id=AUDIT, project_id=PROJECT, baseline_snapshot_id="snap-0", target_snapshot_id="snap-2")
    assert changed.result == "CHANGED"


def test_service_precedence_between_records():
    service = SecurityKnowledgeService()
    historical = service.remember(
        audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-0", source_type="evidence",
        source_id="ev-h", category="OBSERVED_FACT", content={"statement": "older observation"},
    )[0]
    current = service.remember(
        audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-1", source_type="evidence",
        source_id="ev-c", category="OBSERVED_FACT", content={"statement": "newer observation"},
    )[0]
    assert service.precedence(historical, current) == "SUPERSEDED"
    assert service.get_record(historical.record_id, audit_id=AUDIT, project_id=PROJECT) is not None
    assert service.staleness(historical, current_snapshot_id="snap-1") == "STALE"


# ---------------- end-to-end ----------------

def test_e2e_c_baseline_to_target_regression():
    """Baseline evidence disappears at the target snapshot: the state
    is DISAPPEARED (complete coverage), the memory keeps both sides,
    and no Finding is produced."""
    service = SecurityKnowledgeService()
    _, baseline = service.remember_regression(
        audit_id=AUDIT, project_id=PROJECT, regression_key=KEY,
        base_snapshot_id="snap-0", target_snapshot_id="snap-1",
        before_digest="aaa1", after_digest="", after_present=False,
    )
    assert baseline.content["state"] == "DISAPPEARED"
    comparison = service.compare_with_baseline(KEY, audit_id=AUDIT, project_id=PROJECT, baseline_snapshot_id="snap-0", target_snapshot_id="snap-1")
    assert comparison.result in COMPARATOR_RESULTS
    assert service.get_record(baseline.record_id, audit_id=AUDIT, project_id=PROJECT) is not None
    assert not hasattr(service, "create_finding")


def test_e2e_f_layer_context_stays_inert_memory():
    """Change/Threat/Agent layer output lands as untrusted context:
    no authority, no trust raise, no Finding surface."""
    service = SecurityKnowledgeService()
    record = service.remember_from_layer(
        "threat-model", audit_id=AUDIT, project_id=PROJECT, source_id="tm-1",
        content={"observation": "trust boundary documented at the gateway"},
    )
    assert record.category == "THREAT_MODEL_OBSERVATION"
    assert record.trust_level == "untrusted"
    assert record.provenance is not None
    assert record.provenance.origin == "layer:threat-model"
    for layer in ("change-analysis", "threat-model", "agent-security"):
        assert service.remember_from_layer(layer, audit_id=AUDIT, project_id=PROJECT, source_id="x", content={"observation": "recorded"}).trust_level == "untrusted"


def test_unknown_layer_rejected():
    service = SecurityKnowledgeService()
    with pytest.raises(Exception) as e:
        service.remember_from_layer("reporting", audit_id=AUDIT, project_id=PROJECT, source_id="r-1")
    assert "unknown context layer" in str(e.value)
