"""Subagent session contracts — POST-T018.

SubagentLifecycle is *coordination* state (where a session stands), never a
second security engine: transitions record progress, they permit nothing.
SubagentHealth.READY means technically available only — never trusted/safe.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")


class SubagentLifecycle(StrEnum):
    STARTING = "starting"
    READY = "ready"
    RUNNING = "running"
    VERIFYING = "verifying"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RECOVERING = "recovering"
    QUARANTINED = "quarantined"
    UNAVAILABLE = "unavailable"


class SubagentHealth(StrEnum):
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    BLOCKED = "blocked"


TERMINAL_STATES: frozenset[SubagentLifecycle] = frozenset(
    {
        SubagentLifecycle.COMPLETED,
        SubagentLifecycle.FAILED,
        SubagentLifecycle.CANCELLED,
        SubagentLifecycle.QUARANTINED,
    }
)

ALLOWED_TRANSITIONS: dict[SubagentLifecycle, tuple[SubagentLifecycle, ...]] = {
    SubagentLifecycle.STARTING: (SubagentLifecycle.READY, SubagentLifecycle.QUARANTINED, SubagentLifecycle.UNAVAILABLE),
    SubagentLifecycle.READY: (SubagentLifecycle.RUNNING, SubagentLifecycle.CANCELLED, SubagentLifecycle.QUARANTINED, SubagentLifecycle.UNAVAILABLE),
    SubagentLifecycle.RUNNING: (SubagentLifecycle.VERIFYING, SubagentLifecycle.FAILED, SubagentLifecycle.CANCELLED, SubagentLifecycle.QUARANTINED, SubagentLifecycle.UNAVAILABLE),
    SubagentLifecycle.VERIFYING: (SubagentLifecycle.REPORTING, SubagentLifecycle.FAILED, SubagentLifecycle.CANCELLED, SubagentLifecycle.QUARANTINED),
    SubagentLifecycle.REPORTING: (SubagentLifecycle.COMPLETED, SubagentLifecycle.FAILED, SubagentLifecycle.QUARANTINED),
    SubagentLifecycle.COMPLETED: (),
    SubagentLifecycle.FAILED: (SubagentLifecycle.RECOVERING, SubagentLifecycle.QUARANTINED),
    SubagentLifecycle.CANCELLED: (),
    SubagentLifecycle.RECOVERING: (SubagentLifecycle.READY, SubagentLifecycle.RUNNING, SubagentLifecycle.QUARANTINED, SubagentLifecycle.FAILED),
    SubagentLifecycle.QUARANTINED: (),
    SubagentLifecycle.UNAVAILABLE: (SubagentLifecycle.RECOVERING, SubagentLifecycle.QUARANTINED),
}


class SubagentSession(BaseModel):
    """Frozen session record. Audit/project/snapshot/host-bound."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str = Field(...)
    host_id: str = Field(...)
    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    created: int = Field(ge=0)
    expires: int = Field(ge=0)
    state: SubagentLifecycle = SubagentLifecycle.STARTING
    health: SubagentHealth = SubagentHealth.READY

    @field_validator("session_id", "host_id")
    @classmethod
    def _kebab(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("id must be kebab-case")
        return v

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def assert_binding(self, *, host_id: str, audit_id: str, project_id: str, snapshot_id: str) -> None:
        """Any binding mismatch quarantines the session (fail closed)."""
        if self.audit_id != audit_id:
            raise HostIntegrationError(
                HostErrorCode.SESSION_MISMATCH,
                "session audit binding mismatch",
                reason=f"expected {audit_id!r}",
                quarantine=True,
            )
        if self.host_id != host_id or self.project_id != project_id or self.snapshot_id != snapshot_id:
            raise HostIntegrationError(
                HostErrorCode.SESSION_MISMATCH,
                "session host/project/snapshot binding mismatch",
                quarantine=True,
            )

    def assert_live(self, *, now: int) -> None:
        if now > self.expires:
            raise HostIntegrationError(HostErrorCode.EXPIRED, "session expired")

    def transition(self, to: SubagentLifecycle) -> Self:
        """Coordination-only transition. Records progress, permits nothing."""
        if to not in ALLOWED_TRANSITIONS[self.state]:
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                f"illegal lifecycle transition {self.state.value} -> {to.value}",
            )
        return self.model_copy(update={"state": to})

    def quarantine(self) -> Self:
        if self.state in (SubagentLifecycle.QUARANTINED, SubagentLifecycle.COMPLETED, SubagentLifecycle.CANCELLED):
            return self.model_copy(update={"state": SubagentLifecycle.QUARANTINED}) if self.state == SubagentLifecycle.QUARANTINED else self
        return self.model_copy(update={"state": SubagentLifecycle.QUARANTINED, "health": SubagentHealth.BLOCKED})

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
