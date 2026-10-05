"""Adapter registry — POST-RC-012.

Registration is a contract check, never a permission grant. Every
rejection here is structural: duplicate identity, unknown or
escalating capabilities, missing provenance, missing validation or
health contracts, and non-deterministic result contracts.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.verification.adapter_contracts import (
    ADAPTER_CAPABILITIES,
    ESCALATION_CAPABILITY_TOKENS,
    VerificationAdapter,
    VerificationAdapterCapabilities,
)
from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode


class VerificationAdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[tuple[str, str], VerificationAdapter] = {}

    def register(self, adapter: VerificationAdapter) -> None:
        adapter_id = adapter.id
        version = adapter.version
        if not adapter_id or not version:
            raise StrategyError(StrategyErrorCode.ADAPTER_INVALID_REQUEST, "adapter id and version are required")
        try:
            capabilities = adapter.capabilities()
        except ValueError as e:
            message = str(e)
            if "escalation" in message:
                raise StrategyError(StrategyErrorCode.ADAPTER_ESCALATION, message) from e
            raise StrategyError(StrategyErrorCode.ADAPTER_CAPABILITY_UNKNOWN, message) from e
        except Exception as e:
            raise StrategyError(StrategyErrorCode.ADAPTER_INVALID_REQUEST, f"adapter contract incomplete: {e}") from e
        try:
            health = adapter.health()
            provenance = adapter.provenance
        except Exception as e:
            raise StrategyError(StrategyErrorCode.ADAPTER_INVALID_REQUEST, f"adapter contract incomplete: {e}") from e
        self._check_capabilities(capabilities)
        if not provenance or not provenance.get("provider_identity"):
            raise StrategyError(StrategyErrorCode.PROVENANCE_MISSING, "adapter requires provider provenance")
        if not provenance.get("execution_contract_version"):
            raise StrategyError(StrategyErrorCode.PROVENANCE_MISSING, "adapter requires an execution contract version")
        key = (adapter_id, version)
        if key in self._adapters:
            existing = self._adapters[key]
            if existing is adapter:
                return
            raise StrategyError(StrategyErrorCode.ADAPTER_DUPLICATE, f"duplicate adapter identity: {adapter_id}@{version}")
        if not capabilities.capabilities:
            raise StrategyError(StrategyErrorCode.ADAPTER_INVALID_REQUEST, "empty capability set")
        self._adapters[key] = adapter
        _ = health  # health contract must be callable at registration

    def _check_capabilities(self, capabilities: VerificationAdapterCapabilities) -> None:
        for capability in capabilities.capabilities:
            lowered = capability.lower()
            for token in ESCALATION_CAPABILITY_TOKENS:
                if token in lowered:
                    raise StrategyError(StrategyErrorCode.ADAPTER_ESCALATION, f"capability implies escalation: {capability}")
            if capability not in ADAPTER_CAPABILITIES:
                raise StrategyError(StrategyErrorCode.ADAPTER_CAPABILITY_UNKNOWN, f"unknown capability: {capability}")

    def get(self, adapter_id: str, version: str) -> VerificationAdapter:
        key = (adapter_id, version)
        if key not in self._adapters:
            raise StrategyError(StrategyErrorCode.ADAPTER_VERSION_MISMATCH, f"adapter not registered: {adapter_id}@{version}")
        return self._adapters[key]

    def list(self) -> list[VerificationAdapter]:
        return [self._adapters[key] for key in sorted(self._adapters)]

    def versions(self, adapter_id: str) -> list[str]:
        return sorted(v for (sid, v) in self._adapters if sid == adapter_id)

    def describe(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for adapter in self.list():
            capabilities = adapter.capabilities()
            health = adapter.health()
            out.append({
                "adapter_id": adapter.id,
                "adapter_version": adapter.version,
                "capabilities": list(capabilities.capabilities),
                "supported_target_kinds": list(capabilities.supported_target_kinds),
                "supported_strategy_ids": list(capabilities.supported_strategy_ids),
                "health": health.state,
                "provider_identity": adapter.provenance.get("provider_identity", ""),
                "provider_version": adapter.provenance.get("provider_version", ""),
            })
        return out
