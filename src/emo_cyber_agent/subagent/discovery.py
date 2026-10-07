"""Server identity + capability advertisement contract — POST-T018 (Agent 5A).

Discovery-only contract model: describes *what the server is* and *what it
offers*. No execution, no socket, no policy mutation.

Layout mirrors the canonical MCP surface as DATA (``mcp/protocol.py``
serverInfo/capabilities + ``mcp/tools.py`` TOOL_NAMES), so no live-server
import is needed to build an advertisement.
"""

from __future__ import annotations

import json
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

# ---------------------------------------------------------------------------
# Pinned identity DATA — mirrors mcp/protocol.py as plain data.
# Update here only when the MCP server surface itself versions.
# ---------------------------------------------------------------------------

SERVER_NAME = "emo-cyber-agent"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSIONS: tuple[str, ...] = ("2024-11-05", "2025-03-26", "2025-06-18")

# Version of *this* advertisement shape (tool metadata envelope), not the
# server release. Bumped only on advertisement-schema change.
SURFACE_VERSION = "1.0"


class ToolAdvertisement(BaseModel):
    """One advertised tool: name + capability metadata + safe-default flag."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    description: str = Field(min_length=1, max_length=2000)
    capabilities: tuple[str, ...] = ()
    safe_default: bool = True

    @field_validator("capabilities")
    @classmethod
    def _tokens(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for item in v:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("capability tokens must be non-empty strings")
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)


# Canonical tool table — DATA mirror of the seven cyber_* MCP tools.
# capabilities: negotiation-level tokens the tool exercises (metadata only).
# safe_default: False tools are advertised in the full set but withheld
# from per-task default subsets.
_TOOL_TABLE: tuple[ToolAdvertisement, ...] = (
    ToolAdvertisement(
        name="cyber_audit",
        description="Perform a scoped, read-only security audit of an authorized software project. Read-only.",
        capabilities=("repo.read", "codeintel.read", "evidence.read"),
        safe_default=True,
    ),
    ToolAdvertisement(
        name="cyber_review",
        description="Run a focused, read-only security review of a specific asset or context. Read-only.",
        capabilities=("repo.read", "codeintel.read", "evidence.read"),
        safe_default=True,
    ),
    ToolAdvertisement(
        name="cyber_verify",
        description="Request verification of a finding candidate using policy-approved, read-only methods. Read-only.",
        capabilities=("verification.safe", "evidence.read"),
        safe_default=True,
    ),
    ToolAdvertisement(
        name="cyber_report",
        description="Project Core findings into a JSON, JSONL, or Markdown report. Projection only.",
        capabilities=("report.generate", "evidence.read"),
        safe_default=True,
    ),
    ToolAdvertisement(
        name="cyber_status",
        description="Return read-only runtime status: version, capabilities, and policy posture.",
        capabilities=(),
        safe_default=True,
    ),
    ToolAdvertisement(
        name="cyber_extensions",
        description="Inspect the extension catalog as data (list/describe/resolve/check). Read-only metadata view.",
        capabilities=("evidence.read",),
        safe_default=False,
    ),
    ToolAdvertisement(
        name="cyber_threat_intel",
        description="Run read-only threat-intel triage over caller-supplied data (leak-check/triage/map-technique/exposure-check/coverage). Parse/triage/match/map only; never fetches.",
        capabilities=("evidence.read", "threatintel.read"),
        safe_default=False,
    ),
)

KNOWN_TOOL_NAMES: tuple[str, ...] = tuple(t.name for t in _TOOL_TABLE)

# Per-task default subsets. Keys intentionally mirror
# negotiation.TASK_OFFERS so discovery filtering ties to negotiation offers.
TASK_TOOL_SUBSETS: dict[str, tuple[str, ...]] = {
    "security-review": (
        "cyber_audit",
        "cyber_review",
        "cyber_verify",
        "cyber_report",
        "cyber_status",
    ),
}

_SAFE_DEFAULT_SUBSET: tuple[str, ...] = tuple(t.name for t in _TOOL_TABLE if t.safe_default)


def _lookup(name: str) -> ToolAdvertisement:
    for tool in _TOOL_TABLE:
        if tool.name == name:
            return tool
    raise HostIntegrationError(
        HostErrorCode.INVALID,
        f"unknown tool: {name}",
    )


def list_tools() -> tuple[str, ...]:
    """Canonical advertised tool names, in stable order."""
    return KNOWN_TOOL_NAMES


def describe_tool(name: str) -> ToolAdvertisement:
    """Return the advertisement entry for one tool; unknown names rejected."""
    if not isinstance(name, str) or not name.strip():
        raise HostIntegrationError(HostErrorCode.INVALID, "tool name must be a non-empty string")
    return _lookup(name.strip())


def tools_for_task(task_kind: str) -> tuple[ToolAdvertisement, ...]:
    """Filtered tool subset for a task kind (ties to negotiation offers)."""
    if not isinstance(task_kind, str) or not task_kind.strip():
        raise HostIntegrationError(HostErrorCode.INVALID, "task_kind must be a non-empty string")
    key = task_kind.strip()
    if key not in TASK_TOOL_SUBSETS:
        raise HostIntegrationError(
            HostErrorCode.COMPAT_UNKNOWN,
            f"unknown task kind: {key}",
        )
    return tuple(_lookup(name) for name in TASK_TOOL_SUBSETS[key])


class ServerAdvertisement(BaseModel):
    """Frozen server identity + capability advertisement. Data only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server_name: str = Field(min_length=1, max_length=120)
    server_version: str = Field(min_length=1, max_length=32)
    protocol_versions: tuple[str, ...] = Field(min_length=1)
    tools: tuple[ToolAdvertisement, ...] = Field(min_length=1)
    surface_version: str = Field(min_length=1, max_length=16)

    @field_validator("protocol_versions")
    @classmethod
    def _versions(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for item in v:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("protocol versions must be non-empty strings")
        return v

    @model_validator(mode="after")
    def _unique_tools(self) -> Self:
        names = [t.name for t in self.tools]
        if len(set(names)) != len(names):
            raise ValueError("advertised tools must have unique names")
        return self

    def tool_names(self) -> tuple[str, ...]:
        return tuple(t.name for t in self.tools)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def build_advertisement(
    task_kind: str | None = None,
    only: tuple[str, ...] | list[str] | None = None,
) -> ServerAdvertisement:
    """Build a deterministic advertisement.

    - ``task_kind=None`` + ``only=None`` → full seven-tool set.
    - ``task_kind`` set → filtered per-task subset (unknown kind rejected).
    - ``only`` set → narrowing allow-list (unknown tool rejected).
    - both set → intersection (narrowing-only, never widens the task subset).
    """
    if task_kind is None:
        selected: tuple[ToolAdvertisement, ...] = _TOOL_TABLE
    else:
        selected = tools_for_task(task_kind)

    if only is not None:
        if not isinstance(only, (tuple, list)):
            raise HostIntegrationError(HostErrorCode.INVALID, "only must be a list of tool names")
        wanted: list[str] = []
        for raw in only:
            if not isinstance(raw, str) or not raw.strip():
                raise HostIntegrationError(HostErrorCode.INVALID, "tool names must be non-empty strings")
            name = raw.strip()
            _lookup(name)  # reject unknown tools even if outside the task subset
            if name not in wanted:
                wanted.append(name)
        allowed = {t.name for t in selected}
        selected = tuple(_lookup(name) for name in sorted(set(wanted) & allowed))
        if not selected:
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                "tool filter selects an empty set",
            )

    ordered = tuple(sorted(selected, key=lambda t: t.name))
    return ServerAdvertisement(
        server_name=SERVER_NAME,
        server_version=SERVER_VERSION,
        protocol_versions=PROTOCOL_VERSIONS,
        tools=ordered,
        surface_version=SURFACE_VERSION,
    )
