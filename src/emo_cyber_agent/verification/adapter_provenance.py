"""Adapter provenance — POST-RC-012.

Traces every observation back to an execution source:
VerificationResult → Adapter → Tool Invocation → Provider → Evidence.
A response that cannot be tied to a known execution source is
rejected as unverifiable, not downgraded.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.verification.adapter_contracts import VerificationAdapterResponse
from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode

REQUIRED_PROVENANCE_KEYS: tuple[str, ...] = (
    "adapter_id",
    "adapter_version",
    "provider_identity",
    "provider_version",
    "execution_contract_version",
    "policy_decision_id",
)


class AdapterProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    adapter_id: str = Field(..., min_length=1, max_length=80)
    adapter_version: str = Field(..., min_length=1, max_length=40)
    provider_identity: str = Field(..., min_length=1, max_length=160)
    provider_version: str = Field(default="", max_length=60)
    execution_contract_version: str = Field(..., min_length=1, max_length=40)
    policy_decision_id: str = Field(..., min_length=1, max_length=120)
    tool_invocation_id: str = Field(default="", max_length=160)
    environment_fingerprint: str = Field(default="", max_length=128)

    @property
    def trace(self) -> tuple[str, ...]:
        return (
            f"result:{self.adapter_id}@{self.adapter_version}",
            f"provider:{self.provider_identity}@{self.provider_version}",
            f"contract:{self.execution_contract_version}",
            f"policy:{self.policy_decision_id}",
        )


def build_adapter_provenance(
    *,
    adapter_id: str,
    adapter_version: str,
    provider_identity: str,
    provider_version: str,
    execution_contract_version: str,
    policy_decision_id: str,
    tool_invocation_id: str = "",
    environment_fingerprint: str = "",
) -> AdapterProvenance:
    try:
        return AdapterProvenance(
            adapter_id=adapter_id, adapter_version=adapter_version,
            provider_identity=provider_identity, provider_version=provider_version,
            execution_contract_version=execution_contract_version,
            policy_decision_id=policy_decision_id,
            tool_invocation_id=tool_invocation_id,
            environment_fingerprint=environment_fingerprint,
        )
    except ValueError as e:
        raise StrategyError(StrategyErrorCode.PROVENANCE_MISSING, str(e)) from e


def provenance_of(response: VerificationAdapterResponse) -> AdapterProvenance:
    """Parse and validate response provenance. Missing or mismatched
    provenance makes the response unverifiable."""
    raw = dict(response.provenance or {})
    for key in REQUIRED_PROVENANCE_KEYS:
        if not raw.get(key):
            raise StrategyError(StrategyErrorCode.ADAPTER_UNVERIFIABLE, f"response provenance missing: {key}")
    if raw.get("adapter_id") != response.adapter_id or raw.get("adapter_version") != response.adapter_version:
        raise StrategyError(StrategyErrorCode.ADAPTER_UNVERIFIABLE, "response provenance does not match adapter identity")
    try:
        return AdapterProvenance(
            adapter_id=str(raw["adapter_id"]),
            adapter_version=str(raw["adapter_version"]),
            provider_identity=str(raw["provider_identity"]),
            provider_version=str(raw.get("provider_version", "")),
            execution_contract_version=str(raw["execution_contract_version"]),
            policy_decision_id=str(raw["policy_decision_id"]),
            tool_invocation_id=str(raw.get("tool_invocation_id", "")),
            environment_fingerprint=str(raw.get("environment_fingerprint", "")),
        )
    except (ValueError, KeyError) as e:
        raise StrategyError(StrategyErrorCode.ADAPTER_UNVERIFIABLE, str(e)) from e


def assert_provenance_binds(provenance: AdapterProvenance, *, adapter_id: str, adapter_version: str, policy_decision_id: str) -> None:
    if provenance.adapter_id != adapter_id or provenance.adapter_version != adapter_version:
        raise StrategyError(StrategyErrorCode.ADAPTER_VERSION_MISMATCH, "provenance adapter identity mismatch")
    if provenance.policy_decision_id != policy_decision_id:
        raise StrategyError(StrategyErrorCode.STALE_POLICY, "provenance policy decision mismatch")


def trace(result_provenance: dict[str, Any]) -> tuple[str, ...]:
    provenance = AdapterProvenance(**{k: str(v) for k, v in result_provenance.items() if k in AdapterProvenance.model_fields}) if result_provenance else None
    if provenance is None:
        raise StrategyError(StrategyErrorCode.ADAPTER_UNVERIFIABLE, "no provenance to trace")
    return provenance.trace
