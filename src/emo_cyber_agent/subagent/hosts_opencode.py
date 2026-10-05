"""OpenCode host adapter — POST-T018 (Agent 9A).

Data-only adapter metadata for the OpenCode subagent host. No execution,
no network, no subprocess, no policy logic: this module only describes
registration config, tool naming, safe-default exposure, capability
mapping, protocol-negotiation guidance, and troubleshooting data.

Honesty: OpenCode interop is NOT live-verified; compat status is
``Not-tested`` (see ``compat_matrix.HOST_MATRIX["opencode"]``).
"""

from __future__ import annotations

from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.subagent import discovery
from emo_cyber_agent.subagent.compat_matrix import SupportStatus

HOST_ID = "opencode"
DISPLAY_NAME = "OpenCode"
TRANSPORTS: tuple[str, ...] = ("stdio",)
TOOL_NAMING = "kebab-case"
SESSION_BEHAVIOR = "server-managed"

SUPPORT_STATUS: SupportStatus = SupportStatus.NOT_TESTED
SUPPORT_EVIDENCE = (
    "No contract or environment test names this host; default Not-tested. "
    "See compat_matrix.HOST_MATRIX['opencode']."
)

# OpenCode addresses MCP tools under its own tool namespace; server-side
# cyber_* names are passed through as-is (identity mapping, no rename).
OPENCODE_TOOL_NAMESPACE_NOTE = (
    "OpenCode invokes MCP tools under its host tool namespace; "
    "cyber_* server tool names are exposed as-is with no rename."
)

SERVER_COMMAND = "cyber-agent"
SERVER_ARGS: tuple[str, ...] = ("mcp",)
MCP_SERVER_KEY = "emo-cyber-agent"

SAFE_DEFAULT_TOOLS: tuple[str, ...] = (
    "cyber_audit",
    "cyber_review",
    "cyber_verify",
    "cyber_report",
    "cyber_status",
)
OPT_IN_TOOLS: tuple[str, ...] = ("cyber_extensions",)

TOOL_NAME_MAPPING: dict[str, str] = {
    "cyber_audit": "cyber_audit",
    "cyber_review": "cyber_review",
    "cyber_verify": "cyber_verify",
    "cyber_report": "cyber_report",
    "cyber_status": "cyber_status",
    "cyber_extensions": "cyber_extensions",
}

CAPABILITY_MAPPING: dict[str, tuple[str, ...]] = {
    "cyber_audit": ("repo.read", "codeintel.read", "evidence.read"),
    "cyber_review": ("repo.read", "codeintel.read", "evidence.read"),
    "cyber_verify": ("verification.safe", "evidence.read"),
    "cyber_report": ("report.generate", "evidence.read"),
    "cyber_status": (),
    "cyber_extensions": ("evidence.read",),
}

PROTOCOL_NEGOTIATION_NOTE = (
    "Negotiate the MCP protocol version explicitly via discovery: intersect "
    "the host-offered versions with the server-advertised versions from "
    "discovery.build_advertisement() (discovery.PROTOCOL_VERSIONS) and use "
    "the latest common version. Never assume a version; no common version "
    "means the host must abort, not fall back silently."
)


class TroubleshootingEntry(BaseModel):
    """Frozen troubleshooting datum: symptom + fix. Data only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    issue: str = Field(min_length=1, max_length=120)
    symptom: str = Field(min_length=1, max_length=500)
    fix: str = Field(min_length=1, max_length=500)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)


TROUBLESHOOTING: tuple[TroubleshootingEntry, ...] = (
    TroubleshootingEntry(
        issue="server-not-found",
        symptom="OpenCode reports the emo-cyber-agent MCP server is missing or the command fails to start.",
        fix="Verify 'cyber-agent' is installed and on PATH ('cyber-agent --help'); check the mcpServers registration snippet.",
    ),
    TroubleshootingEntry(
        issue="protocol-version-mismatch",
        symptom="initialize fails or the host reports an unsupported protocol version.",
        fix="Re-run explicit version negotiation via negotiate_protocol_version(); use the latest common version from discovery output; abort if none exists.",
    ),
    TroubleshootingEntry(
        issue="tool-not-visible",
        symptom="cyber_* tools do not appear in OpenCode, or cyber_extensions is unexpectedly present/absent.",
        fix="Confirm default exposure is the 5 safe tools only; cyber_extensions is opt-in. Check the host tool namespace view and re-list via tools/list.",
    ),
)


def get_registration_config() -> dict[str, Any]:
    """Return the OpenCode mcpServers stdio registration snippet as data."""
    return {
        "mcpServers": {
            MCP_SERVER_KEY: {
                "command": SERVER_COMMAND,
                "args": list(SERVER_ARGS),
            }
        }
    }


def get_tool_mapping() -> dict[str, str]:
    """Return a copy of the cyber_* identity tool-name mapping."""
    return dict(TOOL_NAME_MAPPING)


def get_safe_default_tools() -> tuple[str, ...]:
    """Return the 5 safe tools exposed by default (cyber_extensions opt-in)."""
    return SAFE_DEFAULT_TOOLS


def get_capability_mapping() -> dict[str, tuple[str, ...]]:
    """Return a copy of the tool → capability-token mapping (metadata only)."""
    return {tool: tuple(caps) for tool, caps in CAPABILITY_MAPPING.items()}


def get_troubleshooting() -> tuple[TroubleshootingEntry, ...]:
    """Return the troubleshooting entries (data only)."""
    return TROUBLESHOOTING


def is_protocol_supported(version: str) -> bool:
    """Explicit version check against discovery-advertised versions.

    No hardcoded assumption: membership is tested against
    ``discovery.PROTOCOL_VERSIONS`` at call time.
    """
    return isinstance(version, str) and version in tuple(discovery.PROTOCOL_VERSIONS)


def negotiate_protocol_version(host_versions: tuple[str, ...] | list[str]) -> str | None:
    """Intersect host-offered versions with discovery versions; latest common wins.

    Pure helper (no I/O): returns the highest common protocol version, or
    ``None`` when there is no overlap (caller must abort, never silently
    fall back). Unknown/empty input yields ``None``.
    """
    if not isinstance(host_versions, (tuple, list)):
        return None
    offered = [v for v in host_versions if isinstance(v, str) and v.strip()]
    common = [v for v in discovery.PROTOCOL_VERSIONS if v in set(offered)]
    if not common:
        return None
    return common[-1]
