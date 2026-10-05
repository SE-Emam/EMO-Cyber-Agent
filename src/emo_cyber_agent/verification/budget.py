"""Verification resource budgets — POST-RC-012.

Hard upper bounds. A child budget may only narrow its parents:
Task ⊕ Playbook ⊕ Strategy ⊕ Policy ⊕ Runtime → the tightest
value of each field. Nothing in this module can widen anything.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode

BUDGET_FIELDS: tuple[str, ...] = (
    "max_requests",
    "max_duration_s",
    "max_output_bytes",
    "max_redirects",
    "max_payload_size",
    "max_retries",
    "max_graph_depth",
    "max_attempts",
)


class ResourceBudget(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    max_requests: int = Field(default=10, ge=1, le=1000)
    max_duration_s: int = Field(default=30, ge=1, le=600)
    max_output_bytes: int = Field(default=65536, ge=256, le=1_048_576)
    max_redirects: int = Field(default=0, ge=0, le=10)
    max_payload_size: int = Field(default=1024, ge=16, le=65536)
    max_retries: int = Field(default=0, ge=0, le=3)
    max_graph_depth: int = Field(default=4, ge=1, le=64)
    max_attempts: int = Field(default=1, ge=1, le=10)

    def tighten(self, other: ResourceBudget) -> ResourceBudget:
        """Pointwise minimum: the caller can only narrow."""
        return ResourceBudget(**{field: min(getattr(self, field), getattr(other, field)) for field in BUDGET_FIELDS})

    def admits(self, other: ResourceBudget) -> bool:
        return all(getattr(other, field) <= getattr(self, field) for field in BUDGET_FIELDS)

    def used(self, usage: BudgetUsage) -> None:
        for field in BUDGET_FIELDS:
            value = getattr(usage, field)
            limit = getattr(self, field)
            if value > limit:
                raise StrategyError(StrategyErrorCode.BUDGET_EXCEEDED, f"{field}: {value} > {limit}")


class BudgetUsage(BaseModel):
    """Observed consumption. Operational metadata only."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    max_requests: int = Field(default=0, ge=0)
    max_duration_s: int = Field(default=0, ge=0)
    max_output_bytes: int = Field(default=0, ge=0)
    max_redirects: int = Field(default=0, ge=0)
    max_payload_size: int = Field(default=0, ge=0)
    max_retries: int = Field(default=0, ge=0)
    max_graph_depth: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=0, ge=0)


def effective_budget(*budgets: ResourceBudget | None) -> ResourceBudget:
    present = [b for b in budgets if b is not None]
    if not present:
        return ResourceBudget()
    result = present[0]
    for budget in present[1:]:
        result = result.tighten(budget)
    return result


def retry_kind(*, reason: str) -> str:
    """Operational retries exist for transient faults only. A DENY, a
    security failure, or a budget stop never becomes a retry."""
    operational = (
        "timeout", "target-unavailable", "connection-reset", "fixture-missing",
        "tool-missing", "resource-limited", "malformed-output", "env-misconfigured",
        "version-mismatch", "target-changed",
    )
    return "OPERATIONAL_RETRY" if reason in operational else "SECURITY_RETRY"
