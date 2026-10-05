"""Adapter resolution and version binding — POST-RC-012.

Deterministic selection: capabilities ⊇ requirement, target kind
supported, strategy supported, health AVAILABLE, then the lowest
adapter id with the highest semantic version. No model, no
heuristics, no "latest" string anywhere.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.verification.adapter_contracts import (
    AdapterHealthState,
    VerificationAdapter,
    VerificationAdapterRequest,
)
from emo_cyber_agent.verification.adapter_registry import VerificationAdapterRegistry
from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode
from emo_cyber_agent.verification.strategy import VerificationStrategy


class AdapterBinding(BaseModel):
    """Immutable plan ↔ adapter identity binding."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    adapter_id: str = Field(..., min_length=1, max_length=80)
    adapter_version: str = Field(..., min_length=1, max_length=40)
    strategy_id: str = Field(..., min_length=1, max_length=80)
    strategy_version: str = Field(..., min_length=1, max_length=40)
    contract_version: str = Field(default="1.0", max_length=40)


class VerificationAdapterResolver:
    def __init__(self, registry: VerificationAdapterRegistry) -> None:
        self._registry = registry

    def resolve(self, strategy: VerificationStrategy, *, target_kind: str) -> AdapterBound:
        candidates: list[tuple[str, tuple[int, ...], VerificationAdapter]] = []
        for adapter in self._registry.list():
            capabilities = adapter.capabilities()
            if not capabilities.supported_strategy_ids or strategy.id not in capabilities.supported_strategy_ids:
                continue
            if target_kind not in capabilities.supported_target_kinds:
                continue
            missing = [c for c in strategy.required_capabilities if c not in capabilities.capabilities]
            if missing:
                continue
            if not adapter.health().available:
                continue
            candidates.append((adapter.id, _version_key(adapter.version), adapter))
        if not candidates:
            raise StrategyError(
                StrategyErrorCode.ADAPTER_UNKNOWN,
                f"no healthy adapter for {strategy.id} on target {target_kind}",
            )
        candidates.sort(key=lambda item: (item[0], tuple(-p for p in item[1])))
        chosen = candidates[0][2]
        return AdapterBound(chosen, self.bind(strategy, adapter=chosen))

    def bind(self, strategy: VerificationStrategy, *, adapter: VerificationAdapter) -> AdapterBinding:
        capabilities = adapter.capabilities()
        return AdapterBinding(
            adapter_id=adapter.id,
            adapter_version=adapter.version,
            strategy_id=strategy.id,
            strategy_version=strategy.version,
            contract_version=capabilities.contract_version,
        )

    def check_binding(self, binding: AdapterBinding, *, adapter: VerificationAdapter) -> None:
        if binding.adapter_id != adapter.id or binding.adapter_version != adapter.version:
            raise StrategyError(StrategyErrorCode.ADAPTER_VERSION_MISMATCH, "adapter identity changed since planning")
        if binding.strategy_version and adapter.id and binding.contract_version != adapter.capabilities().contract_version:
            raise StrategyError(StrategyErrorCode.ADAPTER_VERSION_MISMATCH, "adapter contract version changed since planning")


class AdapterBound:
    """Pair of adapter + binding; resolution output only."""

    def __init__(self, adapter: VerificationAdapter, binding: AdapterBinding) -> None:
        self.adapter = adapter
        self.binding = binding

    @property
    def health(self) -> str:
        return self.adapter.health().state


def assert_request_matches_binding(request: VerificationAdapterRequest, binding: AdapterBinding, *, snapshot_id: str, audit_id: str, project_id: str, policy_decision_id: str) -> None:
    """Every binding field must match, exactly. A caller cannot swap
    identity after planning."""
    if request.strategy_id != binding.strategy_id or request.strategy_version != binding.strategy_version:
        raise StrategyError(StrategyErrorCode.ADAPTER_VERSION_MISMATCH, "request strategy binding mismatch")
    if request.audit_id != audit_id or request.project_id != project_id or request.snapshot_id != snapshot_id:
        raise StrategyError(StrategyErrorCode.AUDIT_MISMATCH, "request scope binding mismatch")
    if request.policy_decision_id != policy_decision_id:
        raise StrategyError(StrategyErrorCode.STALE_POLICY, "request policy binding mismatch")


def assert_adapter_available(adapter: VerificationAdapter) -> None:
    health = adapter.health()
    if health.state != AdapterHealthState.AVAILABLE.value:
        raise StrategyError(StrategyErrorCode.ADAPTER_UNHEALTHY, f"adapter unavailable: {health.state}")


def _version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return (0,)
