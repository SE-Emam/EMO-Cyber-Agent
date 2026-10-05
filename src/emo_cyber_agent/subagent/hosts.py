"""Host profile + compatibility contracts — POST-T018.

HostProfile describes a subagent host (protocol window, transports, tool
naming, session behavior). CompatibilityDecision is the closed verdict of a
compatibility check: UNKNOWN always quarantines — never a silent fallback.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_API_RE = re.compile(r"^\d+\.\d+$")

SUBAGENT_API_VERSION = "1.0"


class CompatibilityVerdict(StrEnum):
    EXACT = "exact"
    MINIMUM = "minimum"
    MAXIMUM = "maximum"
    COMPATIBLE_RANGE = "compatible_range"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class HostProfile(BaseModel):
    """Frozen host description. Identity is kebab-case; versions are semver."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_id: str = Field(...)
    name: str = Field(min_length=1, max_length=120)
    protocol_min: str = Field(default="1.0", max_length=16)
    protocol_max: str = Field(default="", max_length=16)
    transports: tuple[str, ...] = ()
    tool_naming: str = Field(default="kebab-case", max_length=64)
    session_behavior: str = Field(default="server-managed", max_length=64)
    host_version: str = Field(default="0.0.0", max_length=32)

    @field_validator("host_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("host_id must be kebab-case")
        return v

    @field_validator("host_version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _SEMVER_RE.match(v):
            raise ValueError("host_version must be semver X.Y.Z")
        return v

    @field_validator("protocol_min", "protocol_max")
    @classmethod
    def _api(cls, v: str) -> str:
        if v and not _API_RE.match(v):
            raise ValueError("protocol bound must look like X.Y")
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class CompatibilityDecision(BaseModel):
    """Frozen compatibility verdict. UNKNOWN → quarantine, no silent fallback."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_id: str = Field(...)
    verdict: CompatibilityVerdict
    host_version: str = Field(default="", max_length=32)
    required: str = Field(default="", max_length=64)
    reasons: tuple[str, ...] = ()
    evaluated_at: int = Field(ge=0)

    @field_validator("host_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("host_id must be kebab-case")
        return v

    def assert_usable(self) -> None:
        if self.verdict == CompatibilityVerdict.UNKNOWN:
            raise HostIntegrationError(
                HostErrorCode.COMPAT_UNKNOWN,
                "host compatibility unknown — quarantining, no silent fallback",
                quarantine=True,
            )
        if self.verdict == CompatibilityVerdict.INCOMPATIBLE:
            raise HostIntegrationError(
                HostErrorCode.COMPAT_INCOMPATIBLE,
                "host is incompatible",
                quarantine=True,
            )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in version.split("."))
    except ValueError:
        return (0,)


def check_compatibility(profile: HostProfile, *, required_min: str = "", required_max: str = "", evaluated_at: int = 0) -> CompatibilityDecision:
    """Deterministic compatibility check. Unparseable bounds → UNKNOWN."""
    reasons: list[str] = []
    try:
        host_key = _version_key(profile.host_version) if profile.host_version else (0,)
        min_key = _version_key(required_min) if required_min else None
        max_key = _version_key(required_max) if required_max else None
        strict = bool(required_min and not _SEMVER_RE.match(required_min)) or bool(required_max and not _SEMVER_RE.match(required_max))
        if strict:
            raise ValueError("unparseable requirement bound")
        if profile.host_version and not _SEMVER_RE.match(profile.host_version):
            raise ValueError("unparseable host version")
    except ValueError as exc:
        return CompatibilityDecision(
            host_id=profile.host_id,
            verdict=CompatibilityVerdict.UNKNOWN,
            host_version=profile.host_version,
            required=required_min or required_max,
            reasons=(f"unknown: {exc}",),
            evaluated_at=evaluated_at,
        )
    if min_key is not None and host_key < min_key:
        return CompatibilityDecision(
            host_id=profile.host_id,
            verdict=CompatibilityVerdict.INCOMPATIBLE,
            host_version=profile.host_version,
            required=required_min,
            reasons=("host version below required minimum",),
            evaluated_at=evaluated_at,
        )
    if max_key is not None and host_key > max_key:
        return CompatibilityDecision(
            host_id=profile.host_id,
            verdict=CompatibilityVerdict.INCOMPATIBLE,
            host_version=profile.host_version,
            required=required_max,
            reasons=("host version above supported maximum",),
            evaluated_at=evaluated_at,
        )
    if required_min and required_max and required_min == required_max and profile.host_version == required_min:
        verdict = CompatibilityVerdict.EXACT
        reasons.append("exact version match")
    elif required_min and not required_max:
        verdict = CompatibilityVerdict.MINIMUM
        reasons.append("meets minimum version")
    elif required_max and not required_min:
        verdict = CompatibilityVerdict.MAXIMUM
        reasons.append("within maximum version")
    else:
        verdict = CompatibilityVerdict.COMPATIBLE_RANGE
        reasons.append("within compatible range")
    return CompatibilityDecision(
        host_id=profile.host_id,
        verdict=verdict,
        host_version=profile.host_version,
        required=required_min or required_max,
        reasons=tuple(reasons),
        evaluated_at=evaluated_at,
    )
