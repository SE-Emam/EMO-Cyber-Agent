"""Reference verification adapters — POST-RC-012.

Deterministic mock providers behind the adapter contract. They
simulate observations for scripted scenarios; they never touch a
network, a process, a database, or a filesystem, and they cannot
decide a verification state (Core evaluates the typed oracle).

Scenarios: SUPPORTED, REFUTED, INCONCLUSIVE, BLOCKED, TIMEOUT,
MALFORMED_OUTPUT, TARGET_CHANGED, POLICY_DENIED, RESOURCE_LIMITED.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.threat_modeling.spec import canonical_digest
from emo_cyber_agent.verification.adapter_contracts import (
    AdapterExecutionStatus,
    OperationalResult,
    VerificationAdapter,
    VerificationAdapterCapabilities,
    VerificationAdapterHealth,
    VerificationAdapterRequest,
    VerificationAdapterResponse,
)
from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode
from emo_cyber_agent.verification.oracles import VerificationOracle

SCENARIOS: tuple[str, ...] = (
    "SUPPORTED",
    "REFUTED",
    "INCONCLUSIVE",
    "BLOCKED",
    "TIMEOUT",
    "MALFORMED_OUTPUT",
    "TARGET_CHANGED",
    "POLICY_DENIED",
    "RESOURCE_LIMITED",
)

_SCENARIO_MAP: dict[str, tuple[str, str]] = {
    "SUPPORTED": (AdapterExecutionStatus.COMPLETED.value, OperationalResult.OK.value),
    "REFUTED": (AdapterExecutionStatus.COMPLETED.value, OperationalResult.OK.value),
    "INCONCLUSIVE": (AdapterExecutionStatus.COMPLETED.value, OperationalResult.OK.value),
    "BLOCKED": (AdapterExecutionStatus.BLOCKED.value, OperationalResult.POLICY_DENIED.value),
    "TIMEOUT": (AdapterExecutionStatus.TIMEOUT.value, OperationalResult.TIMEOUT.value),
    "MALFORMED_OUTPUT": (AdapterExecutionStatus.MALFORMED.value, OperationalResult.MALFORMED_OUTPUT.value),
    "TARGET_CHANGED": (AdapterExecutionStatus.COMPLETED.value, OperationalResult.TARGET_CHANGED.value),
    "POLICY_DENIED": (AdapterExecutionStatus.BLOCKED.value, OperationalResult.POLICY_DENIED.value),
    "RESOURCE_LIMITED": (AdapterExecutionStatus.FAILED.value, OperationalResult.RESOURCE_LIMITED.value),
}


def _emit(oracle: VerificationOracle, *, supported: bool) -> dict[str, Any]:
    """Simulate an observation that the Core-side oracle will judge.
    Core keeps its own copy of the oracle: adapter output is data."""
    from emo_cyber_agent.verification.oracles import custom_expression, oracle_subject_of

    subject = oracle_subject_of(oracle)
    if oracle.kind == "CUSTOM_ASSERTION":
        key, expected = custom_expression(oracle.assertion)
        opposite = {"true": "false", "false": "true", "deny": "allow", "allow": "deny"}.get(expected, f"not-{expected}")
        return {key: expected if supported else opposite}
    if oracle.operator in ("EXISTS", "NOT_EXISTS"):
        want_present = (oracle.operator == "EXISTS") == supported
        return {subject: want_present}
    if oracle.operator in ("NOT_EQUALS", "NOT_CONTAINS", "ABSENT_FROM_SET"):
        return {subject: f"{oracle.expected}~observed" if supported else oracle.expected}
    return {subject: oracle.expected if supported else f"{oracle.expected}~observed"}


class MockVerificationAdapter(VerificationAdapter):
    """Shared scripted behaviour for every reference adapter."""

    _id = "mock-passive"
    _version = "1.0.0"
    _capabilities: tuple[str, ...] = ()
    _targets: tuple[str, ...] = ()
    _strategies: tuple[str, ...] = ()
    _provider_identity = "emo-mock-provider"
    _provider_version = "1.0.0"

    def __init__(self, scenario: str = "SUPPORTED") -> None:
        if scenario not in SCENARIOS:
            raise StrategyError(StrategyErrorCode.ADAPTER_INVALID_REQUEST, f"unknown scenario: {scenario}")
        self._scenario = scenario

    @property
    def id(self) -> str:
        return self._id

    @property
    def version(self) -> str:
        return self._version

    @property
    def scenario(self) -> str:
        return self._scenario

    @property
    def provenance(self) -> dict[str, Any]:
        return {
            "provider_identity": self._provider_identity,
            "provider_version": self._provider_version,
            "execution_contract_version": "1.0",
            "adapter_id": self._id,
            "adapter_version": self._version,
        }

    def capabilities(self) -> VerificationAdapterCapabilities:
        return VerificationAdapterCapabilities(
            capabilities=self._capabilities,
            supported_target_kinds=self._targets,
            supported_strategy_ids=self._strategies,
        )

    def health(self) -> VerificationAdapterHealth:
        return VerificationAdapterHealth(state="AVAILABLE", provider_version=self._provider_version)

    def validate(self, request: VerificationAdapterRequest) -> None:
        for capability in request.required_capabilities:
            if capability not in self._capabilities:
                raise StrategyError(StrategyErrorCode.ADAPTER_CAPABILITY_UNKNOWN, f"adapter cannot satisfy: {capability}")
        if request.target_kind not in self._targets:
            raise StrategyError(StrategyErrorCode.ADAPTER_INVALID_REQUEST, f"unsupported target kind: {request.target_kind}")
        if self._strategies and request.strategy_id not in self._strategies:
            raise StrategyError(StrategyErrorCode.ADAPTER_INVALID_REQUEST, f"unsupported strategy: {request.strategy_id}")
        if request.safety_level not in ("PASSIVE", "SAFE_ACTIVE", "RESTRICTED_ACTIVE"):
            raise StrategyError(StrategyErrorCode.UNSAFE_LEVEL, "unknown safety level")

    def execute(self, request: VerificationAdapterRequest) -> VerificationAdapterResponse:
        self.validate(request)
        oracle = _oracle_from(request)
        status, operational = _SCENARIO_MAP[self._scenario]
        oracle_inputs: dict[str, Any] = {}
        observations: dict[str, Any] = {"scenario": self._scenario, "strategy": request.strategy_id}
        limitations: tuple[str, ...] = ()
        coverage = "complete"
        if oracle is not None:
            if self._scenario == "SUPPORTED":
                oracle_inputs = _emit(oracle, supported=True)
            elif self._scenario == "REFUTED":
                oracle_inputs = _emit(oracle, supported=False)
            elif self._scenario == "INCONCLUSIVE":
                oracle_inputs, coverage = {}, "partial"
                limitations = ("observation not produced by provider",)
        if self._scenario in ("TIMEOUT", "MALFORMED_OUTPUT", "TARGET_CHANGED", "RESOURCE_LIMITED"):
            coverage = "partial"
            limitations = (f"operational result: {operational.lower()}",)
        raw = canonical_digest({"oracle": oracle_inputs, "obs": observations, "status": status})
        return VerificationAdapterResponse(
            adapter_id=self._id,
            adapter_version=self._version,
            verification_id=request.verification_id,
            status=status,
            observations=observations,
            oracle_inputs=oracle_inputs,
            raw_digest=raw,
            normalized_output=f"scenario={self._scenario}; strategy={request.strategy_id}; target={request.target_identity}",
            coverage=coverage,
            limitations=limitations,
            operational_result=operational,
            provenance={
                **self.provenance,
                "policy_decision_id": request.policy_decision_id,
                "tool_invocation_id": f"mock-{self._id}-{request.verification_id}",
            },
        )


def _oracle_from(request: VerificationAdapterRequest) -> VerificationOracle | None:
    spec = request.normalized_inputs.get("oracle")
    if not isinstance(spec, dict):
        return None
    try:
        return VerificationOracle(**spec)
    except (ValueError, TypeError):
        return None


class MockPassiveAdapter(MockVerificationAdapter):
    _id = "mock-passive"
    _capabilities = ("FILE_ASSERTION", "CONFIG_ASSERTION", "STRUCTURED_TOOL_ASSERTION", "GRAPH_ASSERTION")
    _targets = ("FILE", "SYMBOL", "REPOSITORY", "CONFIGURATION", "DEPENDENCY", "SNAPSHOT")
    _strategies = (
        "static-property-check", "structural-consistency", "configuration-property",
        "dependency-resolution", "secret-exposure", "regression-check", "data-flow-confirmation",
        "interpreter-boundary", "deserialization-boundary",
    )


class MockHttpAdapter(MockVerificationAdapter):
    _id = "mock-http"
    _capabilities = ("HTTP_REQUEST", "HTTP_ASSERTION")
    _targets = ("ROUTE", "API_OPERATION", "ENDPOINT")
    _strategies = (
        "input-boundary", "output-encoding", "authentication-boundary", "ssrf-boundary",
        "sql-injection-safe", "command-injection-safe", "template-injection-safe",
    )


class MockAuthzAdapter(MockVerificationAdapter):
    _id = "mock-authz"
    _capabilities = ("AUTHZ_MATRIX", "SYNTHETIC_IDENTITY_TEST")
    _targets = ("ROUTE", "API_OPERATION", "AGENT_BOUNDARY", "MCP_TOOL", "ENDPOINT")
    _strategies = ("authorization-matrix", "function-authorization", "state-change-authorization")


class MockConfigAdapter(MockVerificationAdapter):
    _id = "mock-config"
    _capabilities = ("CONFIG_ASSERTION", "FILE_ASSERTION", "STRUCTURED_TOOL_ASSERTION")
    _targets = ("CONFIGURATION", "DEPENDENCY", "FILE", "REPOSITORY")
    _strategies = (
        "configuration-property", "dependency-resolution", "secret-exposure", "path-traversal-boundary",
        "interpreter-boundary", "deserialization-boundary", "regression-check",
    )


class MockGraphAdapter(MockVerificationAdapter):
    _id = "mock-graph"
    _capabilities = ("GRAPH_ASSERTION", "AGENT_BOUNDARY_ASSERTION", "MCP_ASSERTION", "STRUCTURED_TOOL_ASSERTION", "FILE_ASSERTION")
    _targets = ("AGENT_BOUNDARY", "MCP_TOOL", "MCP_RESOURCE", "SNAPSHOT", "SYMBOL", "FILE")
    _strategies = (
        "mcp-scope", "mcp-tool-output-isolation", "agent-delegation-scope", "agent-context-isolation",
        "regression-check", "structural-consistency", "data-flow-confirmation",
    )


REFERENCE_ADAPTER_TYPES: tuple[type[MockVerificationAdapter], ...] = (
    MockPassiveAdapter,
    MockHttpAdapter,
    MockAuthzAdapter,
    MockConfigAdapter,
    MockGraphAdapter,
)


def build_reference_adapters(scenario: str = "SUPPORTED") -> list[MockVerificationAdapter]:
    return [adapter_type(scenario) for adapter_type in REFERENCE_ADAPTER_TYPES]
