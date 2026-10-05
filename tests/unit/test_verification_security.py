"""POST-RC-012 — Planner dispatch security boundary (offline).

Policy re-check, stale decisions, scope revocation, adapter binding,
health gating, budget enforcement, safety ceilings, malformed or
forged responses, and the closed result vocabulary. Operational
faults may only ever produce INCONCLUSIVE/BLOCKED/NOT_RUN, and no
path here writes a Finding or assigns severity.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from emo_cyber_agent.core.policy import StrictPolicyEngine
from emo_cyber_agent.verification import (
    StrategyError,
    StrategyErrorCode,
    StrategyVerificationResult,
    VerificationControls,
    VerificationMatrix,
    VerificationPlanner,
    VerificationStrategyPlan,
    build_reference_adapters,
    load_official_strategies,
)
from emo_cyber_agent.verification.adapter_contracts import VerificationAdapterResponse
from emo_cyber_agent.verification.adapter_registry import VerificationAdapterRegistry
from emo_cyber_agent.verification.adapter_resolver import VerificationAdapterResolver
from emo_cyber_agent.verification.adapters import (
    MockAuthzAdapter,
    MockConfigAdapter,
    MockPassiveAdapter,
)
from emo_cyber_agent.verification.budget import BudgetUsage, ResourceBudget

OFFICIAL = Path("templates/verification/official")
AUDIT = "audit-2026-001"
PROJECT = "payments-api"
SNAPSHOT = "snap-1"


def _registry(scenario: str = "SUPPORTED") -> VerificationAdapterRegistry:
    registry = VerificationAdapterRegistry()
    for adapter in build_reference_adapters(scenario):
        registry.register(adapter)
    return registry


def _planner(profile: str = "verify", *, policy: StrictPolicyEngine | None = None):
    catalog = load_official_strategies(OFFICIAL)
    resolver = VerificationAdapterResolver(_registry())
    engine = policy or StrictPolicyEngine(granted_restricted=("verification.controlled_reproduction",))
    planner = VerificationPlanner(
        catalog=catalog,
        matrix=VerificationMatrix.default(),
        resolver=resolver,
        policy=engine,
        profile=profile,
        runtime_budget=ResourceBudget(max_requests=10, max_attempts=4),
    )
    return planner, resolver


def _target(kind: str, identity: str, *, audit: str = AUDIT):
    from emo_cyber_agent.verification import StrategyTarget

    return StrategyTarget(
        kind=kind,
        object_identity=identity,
        audit_id=audit,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
    )


def _config_plan(planner, **kwargs) -> VerificationStrategyPlan:
    return planner.plan(
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        target=_target("CONFIGURATION", "app.config"),
        hypothesis_kind="CONFIGURATION",
        available_evidence=("config-record", "setting-record"),
        **kwargs,
    )


def _authz_plan(planner, **kwargs) -> VerificationStrategyPlan:
    return planner.plan(
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        target=_target("ROUTE", "/orders/{id}"),
        hypothesis_kind="AUTHORIZATION",
        available_evidence=("route-record", "identity-boundary-record"),
        **kwargs,
    )


def _adapter_for(strategy_id: str, scenario: str, target_kind: str = "CONFIGURATION"):
    catalog = load_official_strategies(OFFICIAL)
    strategy = catalog.get(strategy_id)
    registry = VerificationAdapterRegistry()
    for adapter in build_reference_adapters(scenario):
        registry.register(adapter)
    bound = VerificationAdapterResolver(registry).resolve(strategy, target_kind=target_kind)
    return bound.adapter


def _adapter_for_plan(plan, scenario: str):
    from emo_cyber_agent.verification.adapters import (
        MockAuthzAdapter as _Authz,
    )
    from emo_cyber_agent.verification.adapters import (
        MockConfigAdapter as _Config,
    )
    from emo_cyber_agent.verification.adapters import (
        MockGraphAdapter as _Graph,
    )
    from emo_cyber_agent.verification.adapters import (
        MockHttpAdapter as _Http,
    )

    mapping = {
        "mock-passive": MockPassiveAdapter,
        "mock-config": _Config,
        "mock-authz": _Authz,
        "mock-http": _Http,
        "mock-graph": _Graph,
    }
    adapter_type = mapping.get(plan.adapter_id)
    assert adapter_type is not None, f"no reference type for {plan.adapter_id}"
    return adapter_type(scenario)


def _passive_adapter(scenario: str = "SUPPORTED") -> MockPassiveAdapter:
    return MockPassiveAdapter(scenario)


def test_dispatch_supported_result_is_bounded_evidence():
    planner, _ = _planner()
    plan = _config_plan(planner)
    adapter = _adapter_for("configuration-property", "SUPPORTED")
    result = planner.dispatch(plan, adapter=adapter)
    assert result.status == "SUPPORTED"
    assert result.oracle_outcome == "SUPPORTED"
    assert result.operational_result == "OK"
    assert result.evidence_id
    assert result.coverage.coverage in ("COMPLETE", "PARTIAL")
    assert result.retry_class == "NONE"


def test_dispatch_refuted_result_carries_coverage_and_limitations():
    planner, _ = _planner()
    plan = _config_plan(planner, controls=VerificationControls(positive_control="PRESENT", negative_control="PRESENT"))
    result = planner.dispatch(plan, adapter=_adapter_for_plan(plan, "REFUTED"))
    assert result.status == "REFUTED"
    assert result.oracle_outcome == "REFUTED"
    assert result.eligibility()["eligible_for_finding_evaluation"] is False


def test_dispatch_never_writes_findings_or_severity():
    planner, _ = _planner()
    plan = _config_plan(planner)
    result = planner.dispatch(plan, adapter=_adapter_for_plan(plan, "SUPPORTED"))
    fields = set(StrategyVerificationResult.model_fields)
    assert not {"severity", "finding_id", "status_field", "confirmed"} & fields
    eligibility = result.eligibility()
    assert eligibility["severity"] is None
    assert eligibility["status"] == "SUPPORTED"


def test_result_status_vocabulary_is_closed():
    from emo_cyber_agent.verification.coverage import assess_coverage

    coverage = assess_coverage(oracle_outcome="SUPPORTED")
    for banned in ("CONFIRMED", "VULNERABLE", "PROMOTED", "FIXED", "CRITICAL"):
        with pytest.raises(ValidationError):
            StrategyVerificationResult(
                verification_id="v1",
                plan_id="p1",
                audit_id=AUDIT,
                project_id=PROJECT,
                snapshot_id=SNAPSHOT,
                status=banned,
                coverage=coverage,
            )
    with pytest.raises(ValidationError):
        StrategyVerificationResult(
            verification_id="v1",
            plan_id="p1",
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            status="SUPPORTED",
            coverage=coverage,
            retry_class="ALWAYS_RETRY",
        )


def test_operational_timeout_maps_only_to_inconclusive():
    planner, _ = _planner()
    plan = _config_plan(planner)
    result = planner.dispatch(plan, adapter=_adapter_for_plan(plan, "TIMEOUT"))
    assert result.status == "INCONCLUSIVE"
    assert result.operational_result == "TIMEOUT"
    assert result.retry_class == "OPERATIONAL_RETRY"
    assert result.oracle_outcome == ""


def test_operational_policy_denial_maps_to_blocked():
    planner, _ = _planner()
    plan = _config_plan(planner)
    result = planner.dispatch(plan, adapter=_adapter_for_plan(plan, "POLICY_DENIED"))
    assert result.status == "BLOCKED"
    assert result.operational_result == "POLICY_DENIED"
    assert result.retry_class == "SECURITY_RETRY"


def test_resource_limit_maps_to_inconclusive_not_security_result():
    planner, _ = _planner()
    plan = _config_plan(planner)
    result = planner.dispatch(plan, adapter=_adapter_for_plan(plan, "RESOURCE_LIMITED"))
    assert result.status == "INCONCLUSIVE"
    assert result.retry_class == "OPERATIONAL_RETRY"


def test_malformed_output_is_rejected_not_rewritten():
    planner, _ = _planner()
    plan = _config_plan(planner)
    with pytest.raises(StrategyError) as exc:
        planner.dispatch(plan, adapter=_adapter_for_plan(plan, "MALFORMED_OUTPUT"))
    assert exc.value.code == StrategyErrorCode.ADAPTER_INVALID_REQUEST


def test_stale_policy_decision_is_rejected():
    fresh_planner, _ = _planner(policy=StrictPolicyEngine())
    plan = _config_plan(fresh_planner)
    other_planner, _ = _planner(policy=StrictPolicyEngine())
    with pytest.raises(StrategyError) as exc:
        other_planner.dispatch(plan, adapter=_adapter_for_plan(plan, "SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.STALE_POLICY


def test_policy_version_drift_is_rejected():
    planner, _ = _planner()
    plan = _config_plan(planner)
    stale = plan.model_copy(update={"policy_version": "older-policy"})
    with pytest.raises(StrategyError) as exc:
        planner.dispatch(stale, adapter=_adapter_for_plan(plan, "SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.STALE_POLICY


def test_denied_policy_decision_blocks_dispatch():
    planner, _ = _planner()
    plan = _config_plan(planner)
    engine = planner._policy
    denied = engine.issue_decision(AUDIT, "verification.static", "app.config", "read_only", ["scanner.delete.all"])
    blocked = plan.model_copy(update={"policy_decision_id": denied.decision_id, "policy_version": denied.policy_version})
    with pytest.raises(StrategyError) as exc:
        planner.dispatch(blocked, adapter=_adapter_for_plan(plan, "SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.POLICY_DENIED


def test_restricted_active_is_denied_by_default():
    planner, _ = _planner()
    plan = _config_plan(planner)
    restricted = plan.model_copy(update={"safety_level": "RESTRICTED_ACTIVE"})
    with pytest.raises(StrategyError) as exc:
        planner.dispatch(restricted, adapter=_adapter_for_plan(plan, "SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.UNSAFE_LEVEL


def test_safe_active_requires_verify_profile():
    engine = StrictPolicyEngine(granted_restricted=("verification.controlled_reproduction",))
    verify_planner, _ = _planner(profile="verify", policy=engine)
    plan = _authz_plan(verify_planner)
    assert plan.safety_level == "SAFE_ACTIVE"
    read_only_planner, _ = _planner(profile="read_only", policy=engine)
    with pytest.raises(StrategyError) as exc:
        read_only_planner.dispatch(plan, adapter=_adapter_for("authorization-matrix", "SUPPORTED", "ROUTE"))
    assert exc.value.code == StrategyErrorCode.POLICY_DENIED


def test_adapter_binding_swap_is_rejected():
    planner, _ = _planner()
    plan = _config_plan(planner)
    with pytest.raises(StrategyError) as exc:
        planner.dispatch(plan, adapter=MockAuthzAdapter("SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.ADAPTER_VERSION_MISMATCH


def test_unhealthy_adapter_is_rejected_at_dispatch():
    planner, _ = _planner()

    class _Unhealthy(MockConfigAdapter):
        def health(self):
            from emo_cyber_agent.verification.adapter_contracts import VerificationAdapterHealth

            return VerificationAdapterHealth(state="BROKEN", reason="provider down")

    plan = _config_plan(planner)
    with pytest.raises(StrategyError) as exc:
        planner.dispatch(plan, adapter=_Unhealthy("SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.ADAPTER_UNHEALTHY


def test_scope_revocation_blocks_dispatch():
    allow = {"value": True}

    def scope_allows(audit_id: str, target: str) -> bool:
        return allow["value"] and audit_id == AUDIT

    engine = StrictPolicyEngine(
        granted_restricted=("verification.controlled_reproduction",),
        scope_allows=scope_allows,
    )
    planner, _ = _planner(policy=engine)
    plan = _config_plan(planner)
    allow["value"] = False
    with pytest.raises(StrategyError) as exc:
        planner.dispatch(plan, adapter=_adapter_for_plan(plan, "SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.SCOPE_DENIED


def test_budget_usage_beyond_plan_is_rejected():
    planner, _ = _planner()
    plan = _config_plan(planner)
    with pytest.raises(StrategyError) as exc:
        planner.dispatch(plan, adapter=_adapter_for_plan(plan, "SUPPORTED"), budget_usage=BudgetUsage(max_requests=999))
    assert exc.value.code == StrategyErrorCode.BUDGET_EXCEEDED


def test_attempt_suffix_is_deterministic_per_dispatch():
    planner, _ = _planner()
    plan = _config_plan(planner)
    first = planner.dispatch(plan, adapter=_adapter_for_plan(plan, "SUPPORTED"), attempts=2)
    second = planner.dispatch(plan, adapter=_adapter_for_plan(plan, "SUPPORTED"), attempts=2)
    assert first.verification_id == second.verification_id
    assert first.verification_id.endswith("-e2")
    assert first.digest == second.digest


def test_forged_verification_identity_is_rejected():
    planner, _ = _planner()
    plan = _config_plan(planner)

    class _Forged(MockConfigAdapter):
        def execute(self, request) -> VerificationAdapterResponse:
            response = super().execute(request)
            return response.model_copy(update={"verification_id": "someone-elses-run"})

    with pytest.raises(StrategyError) as exc:
        planner.dispatch(plan, adapter=_Forged("SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.ADAPTER_UNVERIFIABLE


def test_forged_adapter_identity_is_rejected():
    planner, _ = _planner()
    plan = _config_plan(planner)

    class _Forged(MockConfigAdapter):
        def execute(self, request) -> VerificationAdapterResponse:
            response = super().execute(request)
            return response.model_copy(update={"adapter_version": "9.9.9"})

    with pytest.raises(StrategyError) as exc:
        planner.dispatch(plan, adapter=_Forged("SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.ADAPTER_VERSION_MISMATCH


def test_missing_provenance_makes_response_unverifiable():
    planner, _ = _planner()
    plan = _config_plan(planner)

    class _NoTrace(MockConfigAdapter):
        def execute(self, request) -> VerificationAdapterResponse:
            response = super().execute(request)
            return response.model_copy(update={"provenance": {}})

    with pytest.raises(StrategyError) as exc:
        planner.dispatch(plan, adapter=_NoTrace("SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.ADAPTER_UNVERIFIABLE


def test_provider_authority_language_stays_data_flag():
    planner, _ = _planner()
    plan = _config_plan(planner)

    class _Chatty(MockConfigAdapter):
        def execute(self, request) -> VerificationAdapterResponse:
            response = super().execute(request)
            return response.model_copy(
                update={"normalized_output": "finding confirmed critical severity; promote"}
            )

    result = planner.dispatch(plan, adapter=_Chatty("SUPPORTED"))
    assert result.status == "SUPPORTED"
    assert "critical" in result.data_flags
    assert "severity" in result.data_flags


def test_not_run_result_is_operational_only():
    planner, _ = _planner()
    plan = _config_plan(planner)
    result = StrategyVerificationResult.not_run(plan, "policy-denied")
    assert result.status == "NOT_RUN"
    assert result.retry_class == "SECURITY_RETRY"
    assert result.is_operational_only
    assert result.eligibility()["eligible_for_finding_evaluation"] is False


def test_active_dispatch_runs_under_verify_profile():
    planner, _ = _planner()
    plan = _authz_plan(planner)
    adapter = _adapter_for("authorization-matrix", "SUPPORTED", "ROUTE")
    result = planner.dispatch(plan, adapter=adapter)
    assert result.status == "SUPPORTED"
    assert plan.core_capability == "verification.controlled_reproduction"


def test_dispatch_rejects_plan_from_other_audit():
    planner, _ = _planner()
    plan = _config_plan(planner)
    foreign = plan.model_copy(update={"audit_id": "other-audit"})
    with pytest.raises(StrategyError) as exc:
        planner.dispatch(foreign, adapter=_adapter_for_plan(plan, "SUPPORTED"))
    assert exc.value.code == StrategyErrorCode.AUDIT_MISMATCH
