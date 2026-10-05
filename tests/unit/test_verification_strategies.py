"""POST-RC-012 — Verification strategies, matrix, and planning (offline).

Closed vocabularies, category safety ceilings, deterministic digests,
budget narrowing, typed oracles, the hypothesis matrix, official
catalog integrity, and deterministic model-free selection. No
network, no findings, no severity.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from emo_cyber_agent.core.policy import StrictPolicyEngine
from emo_cyber_agent.verification import (
    CUSTOM_ASSERTIONS,
    HYPOTHESIS_KINDS,
    StrategyCatalog,
    StrategyError,
    StrategyErrorCode,
    StrategyProvenance,
    StrategyTarget,
    VerificationMatrix,
    VerificationOracle,
    VerificationPlanner,
    assess_coverage,
    authorization_cells,
    build_strategy,
    effective_budget,
    evaluate_oracle,
    expected_decision,
    load_official_strategies,
    load_strategy,
    load_strategy_file,
    oracle_subject_of,
    retry_kind,
    strategies_for_agent,
    strategies_for_change,
    strategies_for_pack,
    strategies_for_threat,
)
from emo_cyber_agent.verification.adapter_registry import VerificationAdapterRegistry
from emo_cyber_agent.verification.adapter_resolver import VerificationAdapterResolver
from emo_cyber_agent.verification.adapters import build_reference_adapters
from emo_cyber_agent.verification.budget import BudgetUsage, ResourceBudget
from emo_cyber_agent.verification.coverage import (
    CONCLUSION_CEILING,
    CoverageAssessment,
    VerificationControls,
)
from emo_cyber_agent.verification.matrix import (
    AGENT_STRATEGY_MAP,
    CHANGE_STRATEGY_MAP,
    DeclaredAuthorization,
    MatrixRow,
    object_authorization_expectation,
    row_oracle_subject,
)
from emo_cyber_agent.verification.oracles import OracleOutcome, oracle_from_spec

OFFICIAL = Path("templates/verification/official")
STARTER = Path("templates/verification/VERIFICATION-STRATEGY.yaml")

AUDIT = "audit-2026-001"
PROJECT = "payments-api"
SNAPSHOT = "snap-1"


def _registry(scenario: str = "SUPPORTED") -> VerificationAdapterRegistry:
    registry = VerificationAdapterRegistry()
    for adapter in build_reference_adapters(scenario):
        registry.register(adapter)
    return registry


def _planner(profile: str = "verify") -> tuple[VerificationPlanner, VerificationAdapterResolver]:
    catalog = load_official_strategies(OFFICIAL)
    resolver = VerificationAdapterResolver(_registry())
    policy = StrictPolicyEngine(granted_restricted=("verification.controlled_reproduction",))
    planner = VerificationPlanner(
        catalog=catalog,
        matrix=VerificationMatrix.default(),
        resolver=resolver,
        policy=policy,
        profile=profile,
    )
    return planner, resolver


def _target(kind: str, identity: str) -> StrategyTarget:
    return StrategyTarget(
        kind=kind,
        object_identity=identity,
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
    )


def _plan(hypothesis: str, kind: str, identity: str, **kwargs):
    planner, _ = _planner()
    row = VerificationMatrix.default().row(hypothesis)
    kwargs.setdefault("available_evidence", row.required_evidence)
    return planner.plan(
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        target=_target(kind, identity),
        hypothesis_kind=hypothesis,
        **kwargs,
    )


def _base_strategy(**overrides):
    payload = {
        "id": "example-check",
        "version": "1.0.0",
        "name": "Example check",
        "category": "STATIC_PROPERTY_CHECK",
        "applicable_hypotheses": ("CONFIGURATION",),
        "required_evidence": ("config-record",),
        "required_capabilities": ("FILE_ASSERTION",),
        "allowed_safety_levels": ("PASSIVE",),
        "target_contract": ("FILE",),
        "input_contract": ("declared-facts",),
        "oracle_contract": ("FILE_STATE_PROPERTY",),
        "success_criteria": "The declared property is observed on the snapshot.",
        "refutation_criteria": "The declared property is absent from the snapshot.",
        "provenance": StrategyProvenance(source="test"),
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# Strategy contract
# ---------------------------------------------------------------------------

def test_strategy_builds_and_digests_deterministically():
    first = build_strategy(**_base_strategy())
    second = build_strategy(**_base_strategy())
    assert first.digest == second.digest
    assert first.digest and len(first.digest) >= 32


def test_strategy_digest_changes_with_content():
    first = build_strategy(**_base_strategy())
    second = build_strategy(**_base_strategy(name="Different name"))
    assert first.digest != second.digest


def test_strategy_rejects_unknown_category():
    with pytest.raises(StrategyError) as exc:
        build_strategy(**_base_strategy(category="MADE_UP"))
    assert exc.value.code == StrategyErrorCode.INVALID_STRATEGY


def test_strategy_enforces_category_safety_ceiling():
    with pytest.raises(StrategyError) as exc:
        build_strategy(**_base_strategy(category="STATIC_PROPERTY_CHECK", allowed_safety_levels=("SAFE_ACTIVE",)))
    assert exc.value.code == StrategyErrorCode.INVALID_STRATEGY


def test_strategy_rejects_unknown_capability_and_target():
    with pytest.raises(StrategyError):
        build_strategy(**_base_strategy(required_capabilities=("SHELL",)))
    with pytest.raises(StrategyError):
        build_strategy(**_base_strategy(target_contract=("*",)))


def test_strategy_rejects_verdict_vocabulary_in_criteria():
    for field, text in (
        ("success_criteria", "the route is vulnerable to access"),
        ("refutation_criteria", "marked critical by the checker"),
        ("limitations", ("fix confirmed by the tool",)),
    ):
        with pytest.raises(StrategyError) as exc:
            build_strategy(**_base_strategy(**{field: text}))
        assert exc.value.code == StrategyErrorCode.INVALID_STRATEGY


def test_strategy_rejects_non_semver_and_bad_id():
    with pytest.raises(StrategyError):
        build_strategy(**_base_strategy(version="latest"))
    with pytest.raises(StrategyError):
        build_strategy(**_base_strategy(id="Not Kebab"))


def test_strategy_supports_target_and_oracle_helpers():
    strategy = build_strategy(**_base_strategy())
    assert strategy.supports_target("FILE")
    assert not strategy.supports_target("ROUTE")
    assert strategy.supports_oracle("FILE_STATE_PROPERTY")
    assert strategy.max_safety_level == "PASSIVE"
    assert strategy.safety_ceiling == "PASSIVE"


def test_strategy_validation_is_atomic():
    with pytest.raises(StrategyError):
        build_strategy(**_base_strategy(oracle_contract=("NOPE",)))
    # nothing partial can be observed: build_strategy only returns valid models
    assert build_strategy(**_base_strategy()).model_extra is None


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------

def test_budget_tighten_is_pointwise_minimum():
    wide = ResourceBudget(max_requests=10, max_duration_s=60, max_attempts=5)
    narrow = ResourceBudget(max_requests=3, max_duration_s=600, max_attempts=2)
    tight = wide.tighten(narrow)
    assert (tight.max_requests, tight.max_duration_s, tight.max_attempts) == (3, 60, 2)
    assert narrow.tighten(wide).max_requests == 3


def test_budget_admits_and_enforces_usage():
    budget = ResourceBudget(max_requests=2, max_output_bytes=1024)
    assert budget.admits(ResourceBudget(max_requests=1, max_output_bytes=1024))
    assert not budget.admits(ResourceBudget(max_requests=3, max_output_bytes=1024))
    budget.used(BudgetUsage(max_requests=2))
    with pytest.raises(StrategyError) as exc:
        budget.used(BudgetUsage(max_requests=3))
    assert exc.value.code == StrategyErrorCode.BUDGET_EXCEEDED


def test_effective_budget_only_narrows():
    result = effective_budget(ResourceBudget(max_requests=10), None, ResourceBudget(max_requests=4, max_retries=2))
    assert result.max_requests == 4
    assert effective_budget().max_requests == ResourceBudget().max_requests


def test_retry_kind_separates_operational_from_security():
    assert retry_kind(reason="timeout") == "OPERATIONAL_RETRY"
    assert retry_kind(reason="fixture-missing") == "OPERATIONAL_RETRY"
    assert retry_kind(reason="policy-denied") == "SECURITY_RETRY"


# ---------------------------------------------------------------------------
# Oracles
# ---------------------------------------------------------------------------

def test_oracle_compares_deterministically():
    oracle = VerificationOracle(kind="HTTP_STATUS", subject="http_status", operator="EQUALS", expected="403")
    assert evaluate_oracle(oracle, {"http_status": 403}) == (OracleOutcome.SUPPORTED, "equal")
    assert evaluate_oracle(oracle, {"http_status": 200}) == (OracleOutcome.REFUTED, "not-equal")


def test_oracle_missing_observation_is_inconclusive():
    oracle = VerificationOracle(kind="HTTP_STATUS", subject="http_status", operator="EQUALS", expected="403")
    outcome, reason = evaluate_oracle(oracle, {})
    assert outcome == OracleOutcome.INCONCLUSIVE
    assert reason == "observation-missing"


def test_oracle_set_and_existence_operators():
    contains = VerificationOracle(kind="HTTP_BODY_PROPERTY", subject="body", operator="CONTAINS", expected="error")
    assert evaluate_oracle(contains, {"body": "an error occurred"})[0] == OracleOutcome.SUPPORTED
    absent = VerificationOracle(kind="HEADER_PROPERTY", subject="server", operator="NOT_CONTAINS", expected="nginx")
    assert evaluate_oracle(absent, {"server": "nginx"})[0] == OracleOutcome.REFUTED
    exists = VerificationOracle(kind="FILE_STATE_PROPERTY", subject="flag", operator="EXISTS", expected="")
    assert evaluate_oracle(exists, {"flag": "on"})[0] == OracleOutcome.SUPPORTED


def test_custom_assertion_table_is_closed():
    oracle = VerificationOracle(kind="CUSTOM_ASSERTION", subject="ignored", operator="EQUALS", assertion="EXPECTED_DENY")
    assert evaluate_oracle(oracle, {"authz_decision": "deny"})[0] == OracleOutcome.SUPPORTED
    assert evaluate_oracle(oracle, {"authz_decision": "allow"})[0] == OracleOutcome.REFUTED
    assert oracle_subject_of(oracle) == "authz_decision"
    with pytest.raises(ValueError):
        VerificationOracle(kind="CUSTOM_ASSERTION", subject="x", operator="EQUALS", assertion="DROP_TABLE")
    with pytest.raises(StrategyError) as exc:
        oracle_from_spec({"kind": "CUSTOM_ASSERTION", "subject": "x", "operator": "EQUALS", "assertion": "MADE_UP"})
    assert exc.value.code == StrategyErrorCode.ORACLE_REJECTED


def test_oracle_rejects_code_like_input():
    with pytest.raises(ValidationError):
        VerificationOracle(kind="CUSTOM_ASSERTION", subject="eval('x')", operator="EQUALS")
    with pytest.raises(StrategyError):
        oracle_from_spec({"kind": "HTTP_STATUS", "subject": "__import__", "operator": "EQUALS"})


def test_custom_assertion_vocabulary_is_ten_items():
    assert len(CUSTOM_ASSERTIONS) == 10


# ---------------------------------------------------------------------------
# Matrix
# ---------------------------------------------------------------------------

def test_matrix_covers_closed_hypothesis_vocabulary():
    matrix = VerificationMatrix.default()
    assert len(matrix.rows) == 20
    assert {row.hypothesis_kind for row in matrix.rows} == set(HYPOTHESIS_KINDS)


def test_matrix_row_validates_kind_and_oracle():
    with pytest.raises(ValidationError):
        MatrixRow(hypothesis_kind="MADE_UP", refutation_criteria="x")
    with pytest.raises(ValidationError):
        MatrixRow(hypothesis_kind="AUTHORIZATION", oracle_kind="NOPE", refutation_criteria="x")
    with pytest.raises(StrategyError) as exc:
        VerificationMatrix.default().row("NOT_A_HYPOTHESIS")
    assert exc.value.code == StrategyErrorCode.SELECTION_FAILED


def test_matrix_subject_is_stable_for_oracle_kind():
    row = VerificationMatrix.default().row("AUTHORIZATION")
    assert row_oracle_subject(row) == "authz_decision"


def test_declared_authorization_produces_expected_decisions():
    declared = DeclaredAuthorization.from_model({"anonymous": [], "different-owner": ["read"], "administrator": ["read", "delete"]})
    assert expected_decision(declared, identity="anonymous", operation="read") == "DENY"
    assert expected_decision(declared, identity="different-owner", operation="read") == "ALLOW"
    assert expected_decision(declared, identity="different-owner", operation="delete") == "DENY"
    with pytest.raises(StrategyError):
        expected_decision(declared, identity="root", operation="read")
    with pytest.raises(StrategyError):
        DeclaredAuthorization.from_model({"root": ["read"]})


def test_authorization_grid_is_complete():
    declared = DeclaredAuthorization.from_model({"anonymous": []})
    cells = authorization_cells(declared)
    assert len(cells) == 36
    assert sum(1 for cell in cells if cell["expected"] == "ALLOW") == 0


def test_object_authorization_expectation_from_ownership():
    assert object_authorization_expectation(caller_owner="alice", object_owner="alice") == "ALLOW"
    assert object_authorization_expectation(caller_owner="bob", object_owner="alice") == "DENY"
    assert object_authorization_expectation(caller_owner="bob", object_owner="alice", caller_privileged=True) == "ALLOW"
    assert object_authorization_expectation(caller_owner="", object_owner="alice") == "DENY"


def test_change_and_pack_maps_are_consistent():
    assert strategies_for_change(("AUTH_BOUNDARY_CHANGED", "NEW_ROUTE")) == (
        "authorization-matrix",
        "function-authorization",
        "input-boundary",
    )
    assert strategies_for_change(("UNKNOWN_PREDICATE",)) == ()
    assert strategies_for_pack("agent-security-pack") == (
        "mcp-scope",
        "mcp-tool-output-isolation",
        "agent-delegation-scope",
        "agent-context-isolation",
    )
    assert strategies_for_pack("nope") == ()
    assert strategies_for_threat("ELEVATION_OF_PRIVILEGE")
    assert strategies_for_agent("SCOPE_CREEP")


def test_agent_and_threat_maps_reference_known_strategies():
    catalog = load_official_strategies(OFFICIAL)
    for table in (AGENT_STRATEGY_MAP, CHANGE_STRATEGY_MAP):
        for entries in table.values():
            for strategy_id in entries:
                catalog.get(strategy_id)


# ---------------------------------------------------------------------------
# Official catalog
# ---------------------------------------------------------------------------

def test_official_catalog_loads_twenty_four_strategies():
    catalog = load_official_strategies(OFFICIAL)
    assert len(catalog) == 24
    assert "authorization-matrix" in catalog.ids()
    assert "agent-context-isolation" in catalog.ids()


def test_every_matrix_row_resolves_with_reference_adapters():
    catalog = load_official_strategies(OFFICIAL)
    resolver = VerificationAdapterResolver(_registry())
    matrix = VerificationMatrix.default()
    for row in matrix.rows:
        assert row.required_evidence, row.hypothesis_kind
        resolvable = 0
        for strategy_id in row.candidate_strategies:
            strategy = catalog.get(strategy_id)
            assert row.oracle_kind in strategy.oracle_contract, f"{row.hypothesis_kind}/{strategy_id}"
            assert set(strategy.required_evidence) <= set(row.required_evidence), f"{row.hypothesis_kind}/{strategy_id}"
            assert set(row.required_evidence) <= set(row.required_evidence)
            resolver.resolve(strategy, target_kind=row.target_kind)
            resolvable += 1
        assert resolvable >= 1, row.hypothesis_kind


def test_official_strategies_all_declare_official_provenance():
    for path in sorted(OFFICIAL.glob("*.yaml")):
        for strategy in load_strategy_file(path):
            assert strategy.provenance.source == "official"
            assert strategy.provenance.origin


def test_starter_template_loads_as_starter():
    strategy = load_strategy(STARTER)
    assert strategy.provenance.source == "starter"
    assert strategy.allowed_safety_levels == ("PASSIVE",)


def test_list_format_and_single_format_loader(tmp_path):
    single = tmp_path / "one.yaml"
    single.write_text(
        "strategy:\n  id: one-check\n  version: 1.0.0\n  name: One\n  category: STATIC_PROPERTY_CHECK\n"
        "  allowed_safety_levels: [PASSIVE]\n  target_kinds: [FILE]\n  oracle_kinds: [FILE_STATE_PROPERTY]\n"
        "  success_criteria: matches the declared record\n  refutation_criteria: differs from the declared record\n"
        "  provenance: {source: test}\n",
        encoding="utf-8",
    )
    assert load_strategy(single).id == "one-check"

    multi = tmp_path / "many.yaml"
    multi.write_text(
        "strategies:\n"
        "  - id: many-one\n    version: 1.0.0\n    name: Many one\n    category: STATIC_PROPERTY_CHECK\n"
        "    allowed_safety_levels: [PASSIVE]\n    target_kinds: [FILE]\n    oracle_kinds: [FILE_STATE_PROPERTY]\n"
        "    success_criteria: matches the declared record\n    refutation_criteria: differs from the declared record\n"
        "  - id: many-two\n    version: 1.0.0\n    name: Many two\n    category: STATIC_PROPERTY_CHECK\n"
        "    allowed_safety_levels: [PASSIVE]\n    target_kinds: [FILE]\n    oracle_kinds: [FILE_STATE_PROPERTY]\n"
        "    success_criteria: matches the declared record\n    refutation_criteria: differs from the declared record\n"
        "provenance: {source: fixture, catalog: tests}\n",
        encoding="utf-8",
    )
    loaded = load_strategy_file(multi)
    assert [s.id for s in loaded] == ["many-one", "many-two"]
    assert all(s.provenance.source == "fixture" for s in loaded)
    with pytest.raises(StrategyError) as exc:
        load_strategy(multi)
    assert exc.value.code == StrategyErrorCode.CATALOG_INVALID


def test_loader_requires_provenance(tmp_path):
    bare = tmp_path / "bare.yaml"
    bare.write_text(
        "strategy:\n  id: bare-check\n  version: 1.0.0\n  name: Bare\n  category: STATIC_PROPERTY_CHECK\n"
        "  allowed_safety_levels: [PASSIVE]\n  target_kinds: [FILE]\n  oracle_kinds: [FILE_STATE_PROPERTY]\n"
        "  success_criteria: matches the declared record\n  refutation_criteria: differs from the declared record\n",
        encoding="utf-8",
    )
    with pytest.raises(StrategyError) as exc:
        load_strategy(bare)
    assert exc.value.code == StrategyErrorCode.PROVENANCE_MISSING


def test_catalog_registers_versions_deterministically():
    catalog = StrategyCatalog()
    catalog.register(build_strategy(**_base_strategy(version="1.0.0")))
    catalog.register(build_strategy(**_base_strategy(version="1.2.0")))
    catalog.register(build_strategy(**_base_strategy(version="1.10.0")))
    assert catalog.get("example-check").version == "1.10.0"
    assert catalog.get("example-check", "1.0.0").version == "1.0.0"
    with pytest.raises(StrategyError) as exc:
        catalog.get("nope")
    assert exc.value.code == StrategyErrorCode.ADAPTER_UNKNOWN
    with pytest.raises(StrategyError) as exc:
        catalog.register(build_strategy(**_base_strategy(version="1.0.0", name="Conflict")))
    assert exc.value.code == StrategyErrorCode.CATALOG_INVALID


# ---------------------------------------------------------------------------
# Planner selection (deterministic, model-free)
# ---------------------------------------------------------------------------

def test_plan_is_deterministic_across_runs():
    first = _plan("AUTHORIZATION", "ROUTE", "/orders/{id}")
    second = _plan("AUTHORIZATION", "ROUTE", "/orders/{id}")
    assert first.plan_id == second.plan_id
    assert first.digest == second.digest
    assert first.policy_decision_id != "" and first.strategy_id == "authorization-matrix"


def test_plan_binds_single_core_capability_and_safety():
    plan = _plan("CONFIGURATION", "CONFIGURATION", "app.config")
    assert plan.core_capability == "verification.config"
    assert plan.safety_level == "PASSIVE"
    active = _plan("AUTHORIZATION", "ROUTE", "/orders/{id}")
    assert active.core_capability == "verification.controlled_reproduction"
    assert active.safety_level == "SAFE_ACTIVE"


def test_plan_rejects_scope_mismatch():
    planner, _ = _planner()
    target = StrategyTarget(
        kind="CONFIGURATION",
        object_identity="app.config",
        audit_id="other-audit",
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
    )
    with pytest.raises(StrategyError) as exc:
        planner.plan(
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            target=target,
            hypothesis_kind="CONFIGURATION",
            available_evidence=("config-record", "setting-record"),
        )
    assert exc.value.code == StrategyErrorCode.AUDIT_MISMATCH


def test_plan_rejects_snapshot_mismatch():
    planner, _ = _planner()
    with pytest.raises(StrategyError) as exc:
        planner.plan(
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id="snap-other",
            target=_target("CONFIGURATION", "app.config"),
            hypothesis_kind="CONFIGURATION",
            available_evidence=("config-record", "setting-record"),
        )
    assert exc.value.code == StrategyErrorCode.SNAPSHOT_MISMATCH


def test_plan_requires_evidence():
    planner, _ = _planner()
    with pytest.raises(StrategyError) as exc:
        planner.plan(
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            target=_target("CONFIGURATION", "app.config"),
            hypothesis_kind="CONFIGURATION",
            available_evidence=("config-record",),
        )
    assert exc.value.code == StrategyErrorCode.SELECTION_FAILED
    assert "setting-record" in str(exc.value)


def test_plan_rejects_unknown_hypothesis():
    planner, _ = _planner()
    with pytest.raises(StrategyError) as exc:
        planner.plan(
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            target=_target("CONFIGURATION", "app.config"),
            hypothesis_kind="TIME_TRAVEL",
        )
    assert exc.value.code == StrategyErrorCode.SELECTION_FAILED


def test_read_only_profile_skips_active_candidates():
    planner, _ = _planner(profile="read_only")
    with pytest.raises(StrategyError) as exc:
        planner.plan(
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            target=_target("ROUTE", "/orders/{id}"),
            hypothesis_kind="AUTHORIZATION",
            available_evidence=("route-record", "identity-boundary-record"),
        )
    assert exc.value.code == StrategyErrorCode.SELECTION_FAILED


def test_model_suggestion_never_decides_selection():
    plan = _plan(
        "CONFIGURATION",
        "CONFIGURATION",
        "app.config",
        model_suggestion="made-up-strategy",
    )
    assert plan.strategy_id == "configuration-property"
    assert any("model-suggestion:ignored-outside-candidates" in note for note in plan.selection_notes)

    second = _plan("CONFIGURATION", "CONFIGURATION", "app.config", model_suggestion="configuration-property")
    assert second.strategy_id == "configuration-property"
    assert any("matches-deterministic-selection" in note for note in second.selection_notes)

    third = _plan("AUTHORIZATION", "ROUTE", "/orders/{id}", model_suggestion="function-authorization")
    assert third.strategy_id == "authorization-matrix"
    assert any("selection-remains-deterministic" in note for note in third.selection_notes)


def test_plan_tightens_budget_and_records_policy_binding():
    plan = _plan("DEPENDENCY", "DEPENDENCY", "requests==2.31.0")
    assert plan.resource_budget.max_requests <= ResourceBudget().max_requests
    assert plan.policy_decision_id and plan.policy_version
    assert plan.adapter_id.startswith("mock-")


def test_plan_requires_expected_for_status_oracle():
    with pytest.raises(StrategyError) as exc:
        _plan("AUTHENTICATION", "ROUTE", "/login", expected="")
    assert exc.value.code == StrategyErrorCode.ORACLE_REJECTED
    plan = _plan("AUTHENTICATION", "ROUTE", "/login", expected="401")
    assert plan.oracle.expected == "401"
    assert plan.oracle.subject == "http_status"


def test_plan_default_authorization_expectation_is_deny():
    plan = _plan("AUTHORIZATION", "ROUTE", "/orders/{id}")
    assert plan.oracle.expected == "deny"


def test_planner_requires_strict_policy_engine():
    catalog = load_official_strategies(OFFICIAL)
    resolver = VerificationAdapterResolver(_registry())
    with pytest.raises(TypeError):
        VerificationPlanner(
            catalog=catalog,
            matrix=VerificationMatrix.default(),
            resolver=resolver,
            policy=object(),
        )


def test_plan_exposes_controls_and_limitations():
    controls = VerificationControls(positive_control="PRESENT", negative_control="PRESENT", rationale="both controls scripted")
    plan = _plan("CONFIGURATION", "CONFIGURATION", "app.config", controls=controls, limitations=("one-target-only",))
    assert plan.controls.positive_control == "PRESENT"
    assert plan.limitations == ("one-target-only",)


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

def test_coverage_never_exceeds_context_only():
    coverage = assess_coverage(
        oracle_outcome="SUPPORTED",
        controls=VerificationControls(positive_control="PRESENT", negative_control="PRESENT"),
        operational_result="OK",
        response_coverage="complete",
    )
    assert coverage.coverage == "COMPLETE"
    assert coverage.conclusion_ceiling == CONCLUSION_CEILING == "context-only"


def test_missing_control_lowers_coverage():
    coverage = assess_coverage(
        oracle_outcome="SUPPORTED",
        controls=VerificationControls(positive_control="ABSENT", negative_control="PRESENT"),
        operational_result="OK",
        response_coverage="complete",
    )
    assert coverage.coverage == "LIMITED"
    assert "control-missing:conclusion-capped" in coverage.limitations


def test_operational_failure_lowers_coverage():
    coverage = assess_coverage(
        oracle_outcome="SUPPORTED",
        controls=VerificationControls(),
        operational_result="TIMEOUT",
        response_coverage="partial",
    )
    assert coverage.coverage == "LIMITED"
    assert "operational-result:timeout" in coverage.limitations


def test_coverage_rejects_raised_ceiling():
    with pytest.raises(ValidationError):
        CoverageAssessment(
            coverage="COMPLETE",
            controls=VerificationControls(positive_control="PRESENT", negative_control="PRESENT"),
            conclusion_ceiling="security-conclusion",
        )
