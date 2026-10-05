"""POST-RC-012 — Adapter contracts, registry, and resolution (offline).

Frozen request/response contracts, closed capability vocabulary,
escalation refusal, deterministic version binding, health gating,
and provenance traces. Providers return data only; nothing here
opens a transport or grants a permission.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from emo_cyber_agent.verification import (
    ADAPTER_CAPABILITIES,
    AdapterHealthState,
    AdapterProvenance,
    OperationalResult,
    StrategyError,
    StrategyErrorCode,
    VerificationAdapterCapabilities,
    VerificationAdapterContext,
    VerificationAdapterHealth,
    VerificationAdapterRegistry,
    VerificationAdapterRequest,
    VerificationAdapterResolver,
    VerificationAdapterResponse,
    build_adapter_provenance,
    build_reference_adapters,
    load_official_strategies,
    provenance_of,
)
from emo_cyber_agent.verification.adapter_contracts import (
    ESCALATION_CAPABILITY_TOKENS,
    FORBIDDEN_REQUEST_FIELDS,
    AdapterExecutionStatus,
    VerificationAdapter,
    assert_no_code_markers,
    flag_authority_language,
)
from emo_cyber_agent.verification.adapter_resolver import (
    AdapterBinding,
    assert_adapter_available,
    assert_request_matches_binding,
)
from emo_cyber_agent.verification.adapters import (
    SCENARIOS,
    MockAuthzAdapter,
    MockPassiveAdapter,
    MockVerificationAdapter,
)
from emo_cyber_agent.verification.matrix import VerificationMatrix

OFFICIAL = Path("templates/verification/official")

AUDIT = "audit-2026-001"
PROJECT = "payments-api"
SNAPSHOT = "snap-1"


def _request(**overrides) -> VerificationAdapterRequest:
    payload = {
        "verification_id": "vplan-abc-e1",
        "strategy_id": "configuration-property",
        "strategy_version": "1.0.0",
        "audit_id": AUDIT,
        "project_id": PROJECT,
        "snapshot_id": SNAPSHOT,
        "target_kind": "CONFIGURATION",
        "target_identity": "app.config",
        "required_capabilities": ("CONFIG_ASSERTION",),
        "safety_level": "PASSIVE",
        "oracle_contract": ("CONFIG_PROPERTY",),
        "policy_decision_id": "pd-1",
    }
    payload.update(overrides)
    return VerificationAdapterRequest(**payload)


def _registry() -> VerificationAdapterRegistry:
    registry = VerificationAdapterRegistry()
    for adapter in build_reference_adapters("SUPPORTED"):
        registry.register(adapter)
    return registry


class _EscalatingAdapter(MockVerificationAdapter):
    _id = "escalating"
    _capabilities = ("file_delete",)
    _targets = ("FILE",)
    _strategies = ("static-property-check",)


class _UnknownCapAdapter(MockVerificationAdapter):
    _id = "unknown-cap"
    _capabilities = ("MAGIC_ASSERTION",)
    _targets = ("FILE",)
    _strategies = ("static-property-check",)


class _NoProvenanceAdapter(MockVerificationAdapter):
    _id = "no-provenance"

    @property
    def provenance(self) -> dict:
        return {"provider_identity": ""}


class _EmptyCapsAdapter(MockVerificationAdapter):
    _id = "empty-caps"
    _capabilities = ()
    _targets = ("FILE",)
    _strategies = ("static-property-check",)


class _BareAdapter(MockVerificationAdapter):
    _id = "bare"
    _capabilities = ("FILE_ASSERTION", "STRUCTURED_TOOL_ASSERTION")
    _targets = ("FILE",)
    _strategies = ("static-property-check",)

    @property
    def provenance(self) -> dict:
        return {"provider_identity": "bare-provider"}


class _AltAdapter(MockVerificationAdapter):
    _id = "aaa-passive"
    _capabilities = ("FILE_ASSERTION", "STRUCTURED_TOOL_ASSERTION")
    _targets = ("FILE",)
    _strategies = ("static-property-check",)


class _BrokenAdapter(MockVerificationAdapter):
    _id = "broken"
    _capabilities = ("FILE_ASSERTION",)
    _targets = ("FILE",)
    _strategies = ("static-property-check",)

    def health(self) -> VerificationAdapterHealth:
        return VerificationAdapterHealth(state=AdapterHealthState.BROKEN.value, reason="provider exited")


# ---------------------------------------------------------------------------
# Capability contract
# ---------------------------------------------------------------------------

def test_capability_vocabulary_is_closed():
    assert len(ADAPTER_CAPABILITIES) == 12
    capabilities = VerificationAdapterCapabilities(
        capabilities=("FILE_ASSERTION", "FILE_ASSERTION"),
        supported_target_kinds=("FILE",),
        supported_strategy_ids=("static-property-check",),
    )
    assert capabilities.capabilities == ("FILE_ASSERTION",)


def test_escalating_capability_rejected_before_unknown():
    with pytest.raises(ValueError) as exc:
        VerificationAdapterCapabilities(capabilities=("file_delete",))
    assert "escalation" in str(exc.value)
    with pytest.raises(ValueError):
        VerificationAdapterCapabilities(capabilities=("MAGIC_ASSERTION",))
    assert "write" in ESCALATION_CAPABILITY_TOKENS


def test_health_states_are_closed():
    health = VerificationAdapterHealth(state="AVAILABLE")
    assert health.available
    assert not VerificationAdapterHealth(state=AdapterHealthState.POLICY_BLOCKED.value).available
    with pytest.raises(ValidationError):
        VerificationAdapterHealth(state="SORT_OF_AVAILABLE")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_registers_reference_adapters_deterministically():
    registry = _registry()
    assert [a.id for a in registry.list()] == sorted(a.id for a in registry.list())
    assert registry.get("mock-authz", "1.0.0").id == "mock-authz"
    assert registry.versions("mock-passive") == ["1.0.0"]
    described = registry.describe()
    assert described and {"adapter_id", "adapter_version", "health"} <= set(described[0])


def test_registry_refuses_duplicate_identity():
    registry = _registry()
    with pytest.raises(StrategyError) as exc:
        registry.register(MockPassiveAdapter("REFUTED"))
    assert exc.value.code == StrategyErrorCode.ADAPTER_DUPLICATE
    fresh = VerificationAdapterRegistry()
    same = MockPassiveAdapter("SUPPORTED")
    fresh.register(same)
    fresh.register(same)  # identical instance is idempotent
    assert len(fresh.list()) == 1


def test_registry_refuses_escalation_and_unknown_capabilities():
    registry = VerificationAdapterRegistry()
    with pytest.raises(StrategyError) as exc:
        registry.register(_EscalatingAdapter())
    assert exc.value.code == StrategyErrorCode.ADAPTER_ESCALATION
    with pytest.raises(StrategyError) as exc:
        registry.register(_UnknownCapAdapter())
    assert exc.value.code == StrategyErrorCode.ADAPTER_CAPABILITY_UNKNOWN


def test_registry_requires_provenance_and_capabilities():
    registry = VerificationAdapterRegistry()
    with pytest.raises(StrategyError) as exc:
        registry.register(_NoProvenanceAdapter())
    assert exc.value.code == StrategyErrorCode.PROVENANCE_MISSING
    with pytest.raises(StrategyError) as exc:
        registry.register(_EmptyCapsAdapter())
    assert exc.value.code == StrategyErrorCode.ADAPTER_INVALID_REQUEST


def test_registry_requires_complete_contract_and_provider_identity():
    registry = VerificationAdapterRegistry()
    with pytest.raises(StrategyError) as exc:
        registry.register(_BareAdapter())
    assert exc.value.code == StrategyErrorCode.PROVENANCE_MISSING
    with pytest.raises(StrategyError) as exc:
        registry.get("missing", "1.0.0")
    assert exc.value.code == StrategyErrorCode.ADAPTER_VERSION_MISMATCH


def test_registry_refuses_empty_adapter_identity():
    registry = VerificationAdapterRegistry()

    class _NoId(MockVerificationAdapter):
        _id = ""

    with pytest.raises(StrategyError) as exc:
        registry.register(_NoId())
    assert exc.value.code == StrategyErrorCode.ADAPTER_INVALID_REQUEST


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def test_resolver_binds_deterministically_by_id_then_version():
    registry = VerificationAdapterRegistry()
    registry.register(MockPassiveAdapter("SUPPORTED"))
    registry.register(_AltAdapter())
    resolver = VerificationAdapterResolver(registry)
    catalog = load_official_strategies(OFFICIAL)
    strategy = catalog.get("static-property-check")
    bound = resolver.resolve(strategy, target_kind="FILE")
    assert bound.adapter.id == "aaa-passive"  # alphabetically lowest id
    binding = resolver.bind(strategy, adapter=bound.adapter)
    assert binding.strategy_id == strategy.id
    assert binding.adapter_id == "aaa-passive"
    resolver.check_binding(binding, adapter=bound.adapter)
    # second resolution yields the identical binding (no ordering drift)
    assert resolver.resolve(strategy, target_kind="FILE").binding == binding


def test_resolver_skips_unhealthy_and_unsupported_adapters():
    registry = VerificationAdapterRegistry()
    registry.register(_BrokenAdapter())
    resolver = VerificationAdapterResolver(registry)
    catalog = load_official_strategies(OFFICIAL)
    strategy = catalog.get("static-property-check")
    with pytest.raises(StrategyError) as exc:
        resolver.resolve(strategy, target_kind="FILE")
    assert exc.value.code == StrategyErrorCode.ADAPTER_UNKNOWN

    healthy = MockPassiveAdapter("SUPPORTED")
    registry.register(healthy)
    bound = resolver.resolve(strategy, target_kind="FILE")
    assert bound.adapter.id == "mock-passive"
    assert bound.health == "AVAILABLE"


def test_resolver_rejects_unsupported_target_and_strategy():
    registry = _registry()
    resolver = VerificationAdapterResolver(registry)
    catalog = load_official_strategies(OFFICIAL)
    with pytest.raises(StrategyError) as exc:
        resolver.resolve(catalog.get("authorization-matrix"), target_kind="DEPENDENCY")
    assert exc.value.code == StrategyErrorCode.ADAPTER_UNKNOWN


def test_binding_mismatch_is_rejected():
    registry = _registry()
    resolver = VerificationAdapterResolver(registry)
    catalog = load_official_strategies(OFFICIAL)
    strategy = catalog.get("static-property-check")
    adapter = MockPassiveAdapter("SUPPORTED")
    stale = AdapterBinding(
        adapter_id="mock-passive",
        adapter_version="9.9.9",
        strategy_id=strategy.id,
        strategy_version=strategy.version,
    )
    with pytest.raises(StrategyError) as exc:
        resolver.check_binding(stale, adapter=adapter)
    assert exc.value.code == StrategyErrorCode.ADAPTER_VERSION_MISMATCH


def test_unavailable_adapter_is_rejected_at_dispatch_boundary():
    assert_adapter_available(MockPassiveAdapter("SUPPORTED"))

    class _Unavailable(MockPassiveAdapter):
        def health(self) -> VerificationAdapterHealth:
            return VerificationAdapterHealth(state=AdapterHealthState.MISSING.value)

    with pytest.raises(StrategyError) as exc:
        assert_adapter_available(_Unavailable())
    assert exc.value.code == StrategyErrorCode.ADAPTER_UNHEALTHY


# ---------------------------------------------------------------------------
# Request / response contracts
# ---------------------------------------------------------------------------

def test_request_rejects_forbidden_fields():
    with pytest.raises(ValidationError):
        _request(normalized_inputs={"raw_command": "rm -rf /"})
    with pytest.raises(ValidationError):
        _request(normalized_inputs={"policy_override": "granted"})
    with pytest.raises(ValidationError):
        _request(normalized_inputs={"finding_severity": "critical"})
    assert "finding_state" in FORBIDDEN_REQUEST_FIELDS


def test_request_rejects_escalation_like_keys_and_code_markers():
    with pytest.raises(ValidationError):
        _request(normalized_inputs={"delete_all": "1"})
    with pytest.raises(ValidationError):
        _request(normalized_inputs={"payload": "eval(1)"})
    with pytest.raises(ValidationError):
        _request(normalized_inputs={"payload": "__import__('os')"})


def test_request_rejects_wildcard_and_external_targets():
    with pytest.raises(ValidationError):
        _request(target_identity="*")
    with pytest.raises(ValidationError):
        _request(target_identity="https://example.com")
    with pytest.raises(ValidationError):
        _request(target_identity="a/../../etc")


def test_request_rejects_null_byte_and_unknown_safety():
    with pytest.raises(ValidationError):
        _request(target_identity="app\x00.config")
    with pytest.raises(ValidationError):
        _request(safety_level="DANGEROUS")
    with pytest.raises(ValidationError):
        _request(status="CONFIRMED")


def test_response_has_no_authority_fields():
    with pytest.raises(ValidationError):
        VerificationAdapterResponse(
            adapter_id="mock-passive",
            adapter_version="1.0.0",
            verification_id="v1",
            status="COMPLETED",
            severity="critical",
        )
    with pytest.raises(ValidationError):
        VerificationAdapterResponse(
            adapter_id="mock-passive",
            adapter_version="1.0.0",
            verification_id="v1",
            status="CONFIRMED",
        )


def test_response_flags_authority_language_as_data_only():
    response = VerificationAdapterResponse(
        adapter_id="mock-passive",
        adapter_version="1.0.0",
        verification_id="v1",
        status=AdapterExecutionStatus.COMPLETED.value,
        normalized_output="this route is vulnerable and severity critical",
    )
    assert response.data_flags
    assert "vulnerable" in response.data_flags and "critical" in response.data_flags
    assert response.status == "COMPLETED"
    assert flag_authority_language("promote to confirmed") == ("confirmed", "promote")


def test_operational_results_never_claim_security_outcomes():
    response = VerificationAdapterResponse(
        adapter_id="mock-passive",
        adapter_version="1.0.0",
        verification_id="v1",
        status=AdapterExecutionStatus.TIMEOUT.value,
        operational_result=OperationalResult.TIMEOUT.value,
    )
    assert response.operational_result == "TIMEOUT"
    with pytest.raises(ValidationError):
        VerificationAdapterResponse(
            adapter_id="mock-passive",
            adapter_version="1.0.0",
            verification_id="v1",
            status=AdapterExecutionStatus.COMPLETED.value,
            operational_result="VULNERABLE",
        )


def test_code_markers_are_rejected_in_provider_bearing_inputs():
    with pytest.raises(ValueError):
        assert_no_code_markers("os.system('id')")
    assert assert_no_code_markers("normal observation") is None


# ---------------------------------------------------------------------------
# Reference adapters and scenarios
# ---------------------------------------------------------------------------

def test_all_reference_adapters_build_for_every_scenario():
    for scenario in SCENARIOS:
        adapters = build_reference_adapters(scenario)
        assert len(adapters) == 5
        for adapter in adapters:
            registry = VerificationAdapterRegistry()
            registry.register(adapter)
            assert adapter.health().available
            assert adapter.provenance["provider_identity"]


def test_adapter_validate_rejects_unsupported_requests():
    adapter = MockAuthzAdapter("SUPPORTED")
    adapter.validate(
        _request(
            strategy_id="authorization-matrix",
            strategy_version="1.0.0",
            target_kind="ROUTE",
            target_identity="/orders/{id}",
            required_capabilities=("AUTHZ_MATRIX", "SYNTHETIC_IDENTITY_TEST"),
            safety_level="SAFE_ACTIVE",
        )
    )
    with pytest.raises(StrategyError) as exc:
        adapter.validate(
            _request(
                strategy_id="configuration-property",
                strategy_version="1.0.0",
                required_capabilities=("CONFIG_ASSERTION",),
            )
        )
    assert exc.value.code == StrategyErrorCode.ADAPTER_CAPABILITY_UNKNOWN


def test_adapter_execute_returns_bound_response():
    adapter = MockPassiveAdapter("SUPPORTED")
    request = _request(
        strategy_id="static-property-check",
        strategy_version="1.0.0",
        required_capabilities=("FILE_ASSERTION", "STRUCTURED_TOOL_ASSERTION"),
        oracle_contract=("FILE_STATE_PROPERTY",),
        normalized_inputs={
            "oracle": {
                "kind": "FILE_STATE_PROPERTY",
                "subject": "file_state_property",
                "operator": "EQUALS",
                "expected": "true",
            }
        },
    )
    response = adapter.execute(request)
    assert response.verification_id == request.verification_id
    assert response.status == "COMPLETED"
    assert response.operational_result == "OK"
    assert response.oracle_inputs == {"file_state_property": "true"}
    assert response.provenance["policy_decision_id"] == request.policy_decision_id


def test_scenario_map_is_complete_and_scripted():
    assert len(SCENARIOS) == 9
    adapter = MockPassiveAdapter("MALFORMED_OUTPUT")
    response = adapter.execute(_request(strategy_id="static-property-check", strategy_version="1.0.0"))
    assert response.status == "MALFORMED"
    assert response.operational_result == "MALFORMED_OUTPUT"
    with pytest.raises(StrategyError):
        MockPassiveAdapter("INVENTED_SCENARIO")


def test_reference_adapters_cover_every_official_strategy():
    catalog = load_official_strategies(OFFICIAL)
    resolver = VerificationAdapterResolver(_registry())
    matrix = VerificationMatrix.default()
    for row in matrix.rows:
        for strategy_id in row.candidate_strategies:
            resolver.resolve(catalog.get(strategy_id), target_kind=row.target_kind)


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

def test_provenance_trace_and_required_keys():
    provenance = build_adapter_provenance(
        adapter_id="mock-passive",
        adapter_version="1.0.0",
        provider_identity="emo-mock-provider",
        provider_version="1.0.0",
        execution_contract_version="1.0",
        policy_decision_id="pd-1",
        tool_invocation_id="inv-1",
    )
    trace = provenance.trace
    assert trace[0] == "result:mock-passive@1.0.0"
    assert "policy:pd-1" in trace
    assert isinstance(provenance, AdapterProvenance)


def test_missing_provenance_makes_response_unverifiable():
    adapter = MockPassiveAdapter("SUPPORTED")
    request = _request(strategy_id="static-property-check", strategy_version="1.0.0")
    response = adapter.execute(request)
    tampered = response.model_copy(update={"provenance": {"adapter_id": "mock-passive"}})
    with pytest.raises(StrategyError) as exc:
        provenance_of(tampered)
    assert exc.value.code == StrategyErrorCode.ADAPTER_UNVERIFIABLE


def test_provenance_identity_mismatch_is_rejected():
    adapter = MockPassiveAdapter("SUPPORTED")
    response = adapter.execute(_request(strategy_id="static-property-check", strategy_version="1.0.0"))
    provenance = provenance_of(response)
    with pytest.raises(StrategyError) as exc:
        from emo_cyber_agent.verification.adapter_provenance import assert_provenance_binds

        assert_provenance_binds(
            provenance,
            adapter_id="mock-http",
            adapter_version="1.0.0",
            policy_decision_id=response.provenance["policy_decision_id"],
        )
    assert exc.value.code == StrategyErrorCode.ADAPTER_VERSION_MISMATCH
    with pytest.raises(StrategyError):
        from emo_cyber_agent.verification.adapter_provenance import assert_provenance_binds

        assert_provenance_binds(
            provenance,
            adapter_id=provenance.adapter_id,
            adapter_version=provenance.adapter_version,
            policy_decision_id="pd-other",
        )


def test_provenance_adapter_identity_must_match_response():
    adapter = MockPassiveAdapter("SUPPORTED")
    response = adapter.execute(_request(strategy_id="static-property-check", strategy_version="1.0.0"))
    forged = response.model_copy(
        update={
            "provenance": {
                **response.provenance,
                "adapter_id": "other-adapter",
            }
        }
    )
    with pytest.raises(StrategyError) as exc:
        provenance_of(forged)
    assert exc.value.code == StrategyErrorCode.ADAPTER_UNVERIFIABLE


def test_request_binding_assertions():
    request = _request(strategy_id="static-property-check", strategy_version="1.0.0")
    binding = AdapterBinding(
        adapter_id="mock-passive",
        adapter_version="1.0.0",
        strategy_id="static-property-check",
        strategy_version="1.0.0",
    )
    assert_request_matches_binding(
        request,
        binding,
        snapshot_id=SNAPSHOT,
        audit_id=AUDIT,
        project_id=PROJECT,
        policy_decision_id="pd-1",
    )
    with pytest.raises(StrategyError) as exc:
        assert_request_matches_binding(
            request.model_copy(update={"strategy_version": "2.0.0"}),
            binding,
            snapshot_id=SNAPSHOT,
            audit_id=AUDIT,
            project_id=PROJECT,
            policy_decision_id="pd-1",
        )
    assert exc.value.code == StrategyErrorCode.ADAPTER_VERSION_MISMATCH
    with pytest.raises(StrategyError) as exc:
        assert_request_matches_binding(
            request,
            binding,
            snapshot_id="snap-other",
            audit_id=AUDIT,
            project_id=PROJECT,
            policy_decision_id="pd-1",
        )
    assert exc.value.code == StrategyErrorCode.AUDIT_MISMATCH


def test_adapter_context_is_frozen_and_scoped():
    context = VerificationAdapterContext(
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        verification_id="v1",
        policy_version="v1",
        policy_decision_id="pd-1",
        strategy_id="static-property-check",
        strategy_version="1.0.0",
        target_identity="app.config",
    )
    with pytest.raises(ValidationError):
        context.audit_id = "other"
    forged = context.model_copy(update={"audit_id": "other"})
    assert forged.audit_id != context.audit_id


def test_verification_adapter_is_abstract():
    with pytest.raises(TypeError):
        VerificationAdapter()  # type: ignore[abstract]
