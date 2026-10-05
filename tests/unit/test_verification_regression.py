"""POST-RC-012 — Verification regression behaviour (offline).

The regression-check strategy, baseline comparison semantics,
historical-vs-current labelling, evidence redaction, and stable
plan/evidence digests across reloads. Historical verification never
becomes current evidence by reuse.
"""

import json
from pathlib import Path

import pytest

from emo_cyber_agent.core.policy import StrictPolicyEngine
from emo_cyber_agent.verification import (
    StrategyError,
    StrategyErrorCode,
    VerificationMatrix,
    VerificationPlanner,
    build_evidence,
    build_reference_adapters,
    load_official_strategies,
    to_evidence_item,
)
from emo_cyber_agent.verification.adapter_registry import VerificationAdapterRegistry
from emo_cyber_agent.verification.adapter_resolver import VerificationAdapterResolver
from emo_cyber_agent.verification.adapters import MockConfigAdapter, MockPassiveAdapter
from emo_cyber_agent.verification.budget import retry_kind
from emo_cyber_agent.verification.evidence import EvidenceCriteria, EvidenceOracle, historical_label
from emo_cyber_agent.verification.strategy import StrategyTarget

OFFICIAL = Path("templates/verification/official")
FIXTURES = Path("tests/fixtures/verification")


def _fixture() -> dict:
    return json.loads((FIXTURES / "regression_cases.json").read_text())


def _registry(scenario: str = "SUPPORTED") -> VerificationAdapterRegistry:
    registry = VerificationAdapterRegistry()
    for adapter in build_reference_adapters(scenario):
        registry.register(adapter)
    return registry


def _planner(scenario: str = "SUPPORTED") -> tuple[VerificationPlanner, VerificationAdapterResolver]:
    resolver = VerificationAdapterResolver(_registry(scenario))
    planner = VerificationPlanner(
        catalog=load_official_strategies(OFFICIAL),
        matrix=VerificationMatrix.default(),
        resolver=resolver,
        policy=StrictPolicyEngine(),
        profile="read_only",
    )
    return planner, resolver


def _target(snapshot_id: str) -> StrategyTarget:
    data = _fixture()
    return StrategyTarget(
        kind="SNAPSHOT",
        object_identity=data["regression_key"],
        audit_id=data["audit_id"],
        project_id=data["project_id"],
        snapshot_id=snapshot_id,
    )


def _plan(scenario: str = "SUPPORTED", snapshot_id: str | None = None):
    data = _fixture()
    planner, resolver = _planner(scenario)
    plan = planner.plan(
        audit_id=data["audit_id"],
        project_id=data["project_id"],
        snapshot_id=snapshot_id or data["cases"][0]["snapshot_id"],
        target=_target(snapshot_id or data["cases"][0]["snapshot_id"]),
        hypothesis_kind="REGRESSION",
        available_evidence=VerificationMatrix.default().row("REGRESSION").required_evidence,
    )
    return planner, resolver, plan


def _adapter(plan, scenario: str):
    from emo_cyber_agent.verification.adapters import (
        MockAuthzAdapter,
        MockGraphAdapter,
        MockHttpAdapter,
    )

    mapping = {
        "mock-passive": MockPassiveAdapter,
        "mock-config": MockConfigAdapter,
        "mock-graph": MockGraphAdapter,
        "mock-http": MockHttpAdapter,
        "mock-authz": MockAuthzAdapter,
    }
    return mapping[plan.adapter_id](scenario)


def test_regression_row_uses_regression_check_only():
    row = VerificationMatrix.default().row("REGRESSION")
    assert row.candidate_strategies == ("regression-check",)
    assert row.target_kind == "SNAPSHOT"
    assert row.required_evidence == ("historical-verification-record", "current-snapshot-record")
    catalog = load_official_strategies(OFFICIAL)
    strategy = catalog.get("regression-check")
    assert strategy.category == "REGRESSION_CHECK"
    assert strategy.allowed_safety_levels == ("PASSIVE",)
    assert "STRUCTURED_TOOL_RESULT" in strategy.oracle_contract


def test_regression_plans_under_read_only_profile():
    _, _, plan = _plan()
    assert plan.strategy_id == "regression-check"
    assert plan.safety_level == "PASSIVE"
    assert plan.core_capability == "verification.static"


@pytest.mark.parametrize("index", range(4))
def test_regression_cases_follow_adapter_outcome(index):
    case = _fixture()["cases"][index]
    planner, _, plan = _plan(case["adapter_scenario"], snapshot_id=case["snapshot_id"])
    result = planner.dispatch(plan, adapter=_adapter(plan, case["adapter_scenario"]))
    assert result.status == case["expected_status"]
    assert result.snapshot_id == case["snapshot_id"]


@pytest.mark.parametrize("index", [4, 5])
def test_historical_labelling_never_relabels_by_reuse(index):
    case = _fixture()["cases"][index]
    label = historical_label(
        evidence_snapshot_id=case["prior_snapshot"],
        current_snapshot_id=case["current_snapshot"],
    )
    assert label == case["expected_label"]
    assert historical_label(evidence_snapshot_id="", current_snapshot_id="snap-2") == "UNKNOWN"


def test_regression_evidence_binds_snapshot_and_plan():
    planner, _, plan = _plan()
    result = planner.dispatch(plan, adapter=_adapter(plan, "SUPPORTED"))
    assert result.evidence_id
    assert result.provenance["plan_digest"] == plan.digest
    assert result.provenance["strategy"] == "regression-check@1.0.0"


def test_regression_result_digest_is_stable_across_plans():
    _, _, first = _plan()
    _, _, second = _plan()
    assert first.digest == second.digest
    # re-planning binds a fresh policy decision (uuid), so result digests
    # differ across runs while the plan content stays identical
    planner, _, plan = _plan()
    first_result = planner.dispatch(plan, adapter=_adapter(plan, "SUPPORTED"))
    second_result = planner.dispatch(plan, adapter=_adapter(plan, "SUPPORTED"))
    assert first_result.digest == second_result.digest
    assert first_result.verification_id == second_result.verification_id


def test_evidence_redacts_sensitive_output():
    oracle = EvidenceOracle(
        kind="STRUCTURED_TOOL_RESULT",
        subject="structured_tool_result",
        operator="EQUALS",
        expected="matches-declared",
        outcome="SUPPORTED",
        reason_code="equal",
    )
    criteria = EvidenceCriteria(success="baseline equals current", refutation="baseline differs from current")
    evidence = build_evidence(
        verification_id="v1",
        strategy_id="regression-check",
        strategy_version="1.0.0",
        adapter_id="mock-config",
        adapter_version="1.0.0",
        target_kind="SNAPSHOT",
        target_identity="authz-matrix@baseline",
        snapshot_id="snap-2",
        audit_id="audit-2026-regression",
        project_id="payments-api",
        observed="token=ghp_abcdefghijklmnopqrstuvwxyz123456 baseline matched",
        oracle=oracle,
        criteria=criteria,
    )
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in evidence.observed_result
    assert "sensitive-output-redacted" in evidence.limitations
    item = to_evidence_item(evidence, asset_id="asset-1")
    assert item.source_tool == "verification:regression-check"
    assert "ghp_" not in item.content_summary
    assert item.provenance["labels"] == ("verification-evidence",)


def test_evidence_requires_scope_identity():
    oracle = EvidenceOracle(kind="STRUCTURED_TOOL_RESULT", subject="s", operator="EQUALS", outcome="SUPPORTED")
    criteria = EvidenceCriteria(success="x", refutation="y")
    with pytest.raises(StrategyError) as exc:
        build_evidence(
            verification_id="v1",
            strategy_id="regression-check",
            strategy_version="1.0.0",
            adapter_id="",
            adapter_version="",
            target_kind="SNAPSHOT",
            target_identity="k",
            snapshot_id="",
            audit_id="",
            project_id="",
            observed="ok",
            oracle=oracle,
            criteria=criteria,
        )
    assert exc.value.code == StrategyErrorCode.SCOPE_DENIED


def test_evidence_digest_changes_with_observation():
    base = {
        "verification_id": "v1",
        "strategy_id": "regression-check",
        "strategy_version": "1.0.0",
        "adapter_id": "mock-config",
        "adapter_version": "1.0.0",
        "target_kind": "SNAPSHOT",
        "target_identity": "k",
        "snapshot_id": "snap-2",
        "audit_id": "a",
        "project_id": "p",
        "oracle": EvidenceOracle(kind="STRUCTURED_TOOL_RESULT", subject="s", operator="EQUALS", outcome="SUPPORTED"),
        "criteria": EvidenceCriteria(success="x", refutation="y"),
    }
    first = build_evidence(observed="observed-a", **base)
    second = build_evidence(observed="observed-b", **base)
    assert first.digest != second.digest
    assert build_evidence(observed="observed-a", **base).digest == first.digest


def test_retry_classification_for_regression_faults():
    assert retry_kind(reason="timeout") == "OPERATIONAL_RETRY"
    assert retry_kind(reason="target-changed") == "OPERATIONAL_RETRY"
    assert retry_kind(reason="policy-denied") == "SECURITY_RETRY"


def test_unknown_regression_target_is_rejected():
    _planner()
    data = _fixture()
    from emo_cyber_agent.verification import StrategyTarget as _Target

    with pytest.raises(Exception) as exc:
        _Target(
            kind="SNAPSHOT",
            object_identity="*",
            audit_id=data["audit_id"],
            project_id=data["project_id"],
            snapshot_id="snap-2",
        )
    assert isinstance(exc.value, Exception)
