"""Subagent health aggregation — POST-T018.

Pure, deterministic roll-up of per-component health into a single
:class:`SubagentHealth` aggregate. Precedence (highest wins):

    BLOCKED > UNAVAILABLE > DEGRADED > READY

``READY`` means *technically available only* — never trusted, never safe,
and never an authorization statement. Health aggregation performs no
capability evaluation and consults no allow/deny grant: explicit
capability sets are unaffected by the aggregate.

No I/O, no clock, no randomness. Input order does not affect the result.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.subagent.session import SubagentHealth
from emo_cyber_agent.subagent.trust import scan_secret_markers

__all__ = ["ComponentReport", "check_subagent", "for_doctor"]


class ComponentReport(BaseModel):
    """Frozen per-component health observation. Detail is presence-only prose."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    state: SubagentHealth
    detail: str = Field(default="", max_length=300)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("component name must be non-empty")
        return v

    @field_validator("detail")
    @classmethod
    def _detail(cls, v: str) -> str:
        if v and scan_secret_markers(v):
            raise ValueError("detail must not carry secret material")
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _normalize(reports: Sequence[ComponentReport | Mapping[str, Any]]) -> tuple[ComponentReport, ...]:
    """Coerce inputs to validated ComponentReports. Order preserved; pure."""
    normalized: list[ComponentReport] = []
    for item in reports:
        if isinstance(item, ComponentReport):
            normalized.append(item)
        elif isinstance(item, Mapping):
            normalized.append(ComponentReport.model_validate(dict(item)))
        else:
            raise TypeError(f"component report must be ComponentReport or mapping, got {type(item).__name__}")
    return tuple(normalized)


def check_subagent(reports: Sequence[ComponentReport | Mapping[str, Any]] = ()) -> SubagentHealth:
    """Aggregate component reports to a single SubagentHealth.

    Pure and deterministic: no I/O, no clock, input-order independent.
    Empty input aggregates to READY (nothing reported unavailable).
    """
    states = {r.state for r in _normalize(reports)}
    if SubagentHealth.BLOCKED in states:
        return SubagentHealth.BLOCKED
    if SubagentHealth.UNAVAILABLE in states:
        return SubagentHealth.UNAVAILABLE
    if SubagentHealth.DEGRADED in states:
        return SubagentHealth.DEGRADED
    return SubagentHealth.READY


def for_doctor(reports: Sequence[ComponentReport | Mapping[str, Any]] = ()) -> dict[str, str]:
    """Project component reports to a doctor-compatible checks dict.

    Keys/values are plain strings; state tokens use the doctor's UPPERCASE
    style (READY/DEGRADED/UNAVAILABLE/BLOCKED). Detail text is never echoed —
    presence of a component is recorded, never its payload — mirroring the
    ``doctor`` command's never-print-secrets rule. Keys are insertion-sorted
    by component name for deterministic output.
    """
    normalized = _normalize(reports)
    aggregate = check_subagent(normalized)
    checks: dict[str, str] = {"subagent": aggregate.value.upper()}
    for report in sorted(normalized, key=lambda r: r.name):
        checks[f"subagent:{report.name}"] = report.state.value.upper()
    return checks
