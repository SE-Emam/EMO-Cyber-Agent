"""Per-host compatibility matrix — POST-T018 (Agent 8C).

Data + pure evaluator. No execution, no network, no subprocess: this module
only describes claimed per-host compatibility and evaluates a
(host_id, host_version, protocol_version) triple into a
:class:`CompatibilityDecision` reusing the verdicts from ``hosts.py``.

Honesty policy: every host-specific claim that has NOT been verified by a
test or a live environment run is labelled ``NOT_TESTED``. The only entry
with test evidence is ``generic-mcp``, which is exercised by the in-repo
contract tests over the stdio JSON-RPC transport, hence ``CONTRACT_TESTED``.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.mcp.protocol import SUPPORTED_PROTOCOL_VERSIONS
from emo_cyber_agent.subagent.hosts import (
    CompatibilityDecision,
    CompatibilityVerdict,
    HostProfile,
    check_compatibility,
)

_HOST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
# Matrix keys are the canonical host names from the POST-T018 brief, which
# include the 2-character alias "pi". hosts.py requires >=3-char kebab-case
# ids, so decisions/profiles for such aliases use DECISION_HOST_IDS.
_MATRIX_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,78}[a-z0-9])?$")
DECISION_HOST_IDS: dict[str, str] = {"pi": "pi-host"}
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_PROTO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class SupportStatus(StrEnum):
    """Honest test-evidence label for a matrix entry."""

    SUPPORTED = "Supported"
    CONTRACT_TESTED = "Contract-tested"
    ENVIRONMENT_TESTED = "Environment-tested"
    NOT_TESTED = "Not-tested"
    KNOWN_LIMITATION = "Known-limitation"


class HostMatrixEntry(BaseModel):
    """Frozen per-host compatibility row. Pure data, no behavior."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_id: str = Field(...)
    display_name: str = Field(min_length=1, max_length=120)
    protocol_min: str = Field(default="", max_length=16)
    protocol_max: str = Field(default="", max_length=16)
    transports: tuple[str, ...] = ()
    tool_naming: str = Field(default="kebab-case", max_length=64)
    lifecycle_notes: str = Field(default="", max_length=500)
    session_behavior: str = Field(default="server-managed", max_length=64)
    known_limits: tuple[str, ...] = ()
    support_status: SupportStatus = SupportStatus.NOT_TESTED
    support_evidence: str = Field(default="", max_length=500)
    host_version_min: str = Field(default="", max_length=32)
    host_version_max: str = Field(default="", max_length=32)

    @field_validator("host_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _MATRIX_ID_RE.match(v):
            raise ValueError("host_id must be kebab-case")
        return v

    @field_validator("protocol_min", "protocol_max")
    @classmethod
    def _proto(cls, v: str) -> str:
        if v and not _PROTO_RE.match(v):
            raise ValueError("protocol bound must look like YYYY-MM-DD")
        return v

    @field_validator("host_version_min", "host_version_max")
    @classmethod
    def _hostver(cls, v: str) -> str:
        if v and not _SEMVER_RE.match(v):
            raise ValueError("host version bound must be semver X.Y.Z")
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)


_PROTO_MIN = SUPPORTED_PROTOCOL_VERSIONS[0]
_PROTO_MAX = SUPPORTED_PROTOCOL_VERSIONS[-1]

HOST_MATRIX: dict[str, HostMatrixEntry] = {
    "opencode": HostMatrixEntry(
        host_id="opencode",
        display_name="OpenCode",
        protocol_min=_PROTO_MIN,
        protocol_max=_PROTO_MAX,
        transports=("stdio",),
        tool_naming="kebab-case",
        lifecycle_notes="Assumed initialize → notifications/initialized → tools/list → tools/call; not verified against a live host.",
        session_behavior="server-managed",
        known_limits=(
            "No live-host verification performed; interoperability is claimed, not demonstrated.",
            "Host-side tool-name mapping is unverified.",
        ),
        support_status=SupportStatus.NOT_TESTED,
        support_evidence="No contract or environment test names this host; default Not-tested.",
        host_version_min="",
        host_version_max="",
    ),
    "pi": HostMatrixEntry(
        host_id="pi",
        display_name="Pi",
        protocol_min=_PROTO_MIN,
        protocol_max=_PROTO_MAX,
        transports=("stdio",),
        tool_naming="kebab-case",
        lifecycle_notes="Assumed standard MCP lifecycle; not verified against a live host.",
        session_behavior="server-managed",
        known_limits=(
            "No live-host verification performed; interoperability is claimed, not demonstrated.",
        ),
        support_status=SupportStatus.NOT_TESTED,
        support_evidence="No contract or environment test names this host; default Not-tested.",
        host_version_min="",
        host_version_max="",
    ),
    "hermes": HostMatrixEntry(
        host_id="hermes",
        display_name="Hermes",
        protocol_min=_PROTO_MIN,
        protocol_max=_PROTO_MAX,
        transports=("stdio",),
        tool_naming="kebab-case",
        lifecycle_notes="Assumed standard MCP lifecycle; not verified against a live host.",
        session_behavior="server-managed",
        known_limits=(
            "No live-host verification performed; interoperability is claimed, not demonstrated.",
        ),
        support_status=SupportStatus.NOT_TESTED,
        support_evidence="No contract or environment test names this host; default Not-tested.",
        host_version_min="",
        host_version_max="",
    ),
    "jan": HostMatrixEntry(
        host_id="jan",
        display_name="Jan",
        protocol_min=_PROTO_MIN,
        protocol_max=_PROTO_MAX,
        transports=("stdio",),
        tool_naming="kebab-case",
        lifecycle_notes="Assumed standard MCP lifecycle; not verified against a live host.",
        session_behavior="server-managed",
        known_limits=(
            "No live-host verification performed; interoperability is claimed, not demonstrated.",
        ),
        support_status=SupportStatus.NOT_TESTED,
        support_evidence="No contract or environment test names this host; default Not-tested.",
        host_version_min="",
        host_version_max="",
    ),
    "anythingllm": HostMatrixEntry(
        host_id="anythingllm",
        display_name="AnythingLLM",
        protocol_min=_PROTO_MIN,
        protocol_max=_PROTO_MAX,
        transports=("stdio",),
        tool_naming="kebab-case",
        lifecycle_notes="Assumed standard MCP lifecycle; not verified against a live host.",
        session_behavior="server-managed",
        known_limits=(
            "No live-host verification performed; interoperability is claimed, not demonstrated.",
            "Desktop-app transport/wrapping behavior is unverified and may differ.",
        ),
        support_status=SupportStatus.NOT_TESTED,
        support_evidence="No contract or environment test names this host; default Not-tested.",
        host_version_min="",
        host_version_max="",
    ),
    "generic-mcp": HostMatrixEntry(
        host_id="generic-mcp",
        display_name="Generic MCP (tested baseline)",
        protocol_min=_PROTO_MIN,
        protocol_max=_PROTO_MAX,
        transports=("stdio",),
        tool_naming="kebab-case",
        lifecycle_notes="initialize → notifications/initialized → tools/list → tools/call (+ ping); one JSON object per line, logs on stderr.",
        session_behavior="server-managed",
        known_limits=(
            "Baseline covers the stdio JSON-RPC subset only; HTTP/SSE transports are out of scope.",
            "Per-vendor host quirks are explicitly not covered by this entry.",
        ),
        support_status=SupportStatus.CONTRACT_TESTED,
        support_evidence="Exercised by in-repo contract tests (tests/unit/subagent/test_contracts.py, test_mcp_security.py) over the stdio transport.",
        host_version_min="",
        host_version_max="",
    ),
}

_ALLOWED_STATUSES = frozenset(SupportStatus)


def list_hosts() -> tuple[str, ...]:
    """Return sorted host ids in the matrix. Pure, deterministic."""
    return tuple(sorted(HOST_MATRIX))


def get_entry(host_id: str) -> HostMatrixEntry | None:
    """Return the matrix entry for host_id, or None if unknown. Pure lookup."""
    return HOST_MATRIX.get(host_id)


def _proto_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in version.split("-"))
    except ValueError:
        return (0,)


def _decision_id(host_id: str) -> str:
    """Map a matrix key to a hosts.py-legal decision id (see DECISION_HOST_IDS)."""
    if host_id in DECISION_HOST_IDS:
        return DECISION_HOST_IDS[host_id]
    return host_id


def _unknown(host_id: str, host_version: str, required: str, reason: str, evaluated_at: int) -> CompatibilityDecision:
    safe_id = _decision_id(host_id) if _HOST_ID_RE.match(_decision_id(host_id or "")) else "unknown-host"
    return CompatibilityDecision(
        host_id=safe_id,
        verdict=CompatibilityVerdict.UNKNOWN,
        host_version=host_version if isinstance(host_version, str) else "",
        required=required,
        reasons=(reason,),
        evaluated_at=evaluated_at,
    )


def evaluate_compat(
    host_id: str,
    host_version: str,
    protocol_version: str,
    *,
    evaluated_at: int = 0,
) -> CompatibilityDecision:
    """Evaluate (host_id, host_version, protocol_version) → CompatibilityDecision.

    Pure and deterministic: no I/O, no clock, no randomness. UNKNOWN verdicts
    quarantine via :meth:`CompatibilityDecision.assert_usable` — never a
    silent fallback. Host-version windows reuse ``hosts.check_compatibility``
    verdicts; protocol windows are checked here against the entry bounds and
    the server's SUPPORTED_PROTOCOL_VERSIONS.
    """
    entry = HOST_MATRIX.get(host_id or "")
    if entry is None:
        return _unknown(
            host_id or "",
            host_version if isinstance(host_version, str) else "",
            protocol_version if isinstance(protocol_version, str) else "",
            f"unknown: host '{host_id}' is not in the compatibility matrix",
            evaluated_at,
        )
    if not isinstance(host_version, str) or not _SEMVER_RE.match(host_version):
        return _unknown(
            host_id,
            host_version if isinstance(host_version, str) else "",
            protocol_version if isinstance(protocol_version, str) else "",
            f"unknown: host_version '{host_version}' is not semver X.Y.Z",
            evaluated_at,
        )
    if not isinstance(protocol_version, str) or not _PROTO_RE.match(protocol_version):
        return _unknown(
            host_id,
            host_version,
            protocol_version if isinstance(protocol_version, str) else "",
            f"unknown: protocol_version '{protocol_version}' is not a YYYY-MM-DD date",
            evaluated_at,
        )
    if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
        return CompatibilityDecision(
            host_id=_decision_id(host_id),
            verdict=CompatibilityVerdict.INCOMPATIBLE,
            host_version=host_version,
            required=",".join(SUPPORTED_PROTOCOL_VERSIONS),
            reasons=(f"protocol version {protocol_version} is not supported by this server",),
            evaluated_at=evaluated_at,
        )
    if entry.protocol_min and _proto_key(protocol_version) < _proto_key(entry.protocol_min):
        return CompatibilityDecision(
            host_id=_decision_id(host_id),
            verdict=CompatibilityVerdict.INCOMPATIBLE,
            host_version=host_version,
            required=entry.protocol_min,
            reasons=(f"protocol version {protocol_version} below host minimum {entry.protocol_min}",),
            evaluated_at=evaluated_at,
        )
    if entry.protocol_max and _proto_key(protocol_version) > _proto_key(entry.protocol_max):
        return CompatibilityDecision(
            host_id=_decision_id(host_id),
            verdict=CompatibilityVerdict.INCOMPATIBLE,
            host_version=host_version,
            required=entry.protocol_max,
            reasons=(f"protocol version {protocol_version} above host maximum {entry.protocol_max}",),
            evaluated_at=evaluated_at,
        )

    profile = HostProfile(
        host_id=_decision_id(entry.host_id),
        name=entry.display_name,
        protocol_min="1.0",
        protocol_max="",
        transports=entry.transports,
        tool_naming=entry.tool_naming,
        session_behavior=entry.session_behavior,
        host_version=host_version,
    )
    base = check_compatibility(
        profile,
        required_min=entry.host_version_min,
        required_max=entry.host_version_max,
        evaluated_at=evaluated_at,
    )
    reasons = list(base.reasons)
    reasons.append(f"protocol {protocol_version} within host window")
    if entry.host_id in DECISION_HOST_IDS:
        reasons.append(f"matrix alias '{entry.host_id}' reported as '{base.host_id}' (hosts.py id rules)")
    if entry.support_status == SupportStatus.NOT_TESTED:
        reasons.append(f"host '{host_id}' is Not-tested: compatibility is provisional, not demonstrated")
    elif entry.support_status == SupportStatus.KNOWN_LIMITATION:
        reasons.append(f"host '{host_id}' has a known limitation; see known_limits")
    else:
        reasons.append(f"host '{host_id}' support status: {entry.support_status.value}")
    return CompatibilityDecision(
        host_id=base.host_id,
        verdict=base.verdict,
        host_version=base.host_version,
        required=protocol_version,
        reasons=tuple(reasons),
        evaluated_at=base.evaluated_at,
    )
