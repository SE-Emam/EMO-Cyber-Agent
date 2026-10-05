"""Tool pack resolver — POST-RC-007 (deterministic, no LLM).

Task/Playbook required tools → compatible ToolDefinition → runtime
health → policy gate (downstream). Unknown references fail closed;
optional unavailable tools degrade explicitly, never silently.
"""

from __future__ import annotations

import re
import shutil
from typing import Any

from emo_cyber_agent.tools.packs.errors import ToolPackError, ToolPackErrorCode
from emo_cyber_agent.tools.packs.registry import ToolPackRegistry
from emo_cyber_agent.tools.packs.spec import NetworkRequirement, ResolvedTool, ToolDefinition, ToolHealth, ToolHealthReport, ToolPack


def _parse_version(version: str) -> tuple[int, ...]:
    parts = re.split(r"[.\-+]", version.strip())
    numbers: list[int] = []
    for part in parts:
        match = re.match(r"^\d+", part)
        if match is None:
            break
        numbers.append(int(match.group(0)))
    return tuple(numbers) if numbers else (0,)


def satisfies_range(version: str, version_range: str) -> bool:
    """Simple comma-separated specifier check (>=, ==, ~=, >, <, <=)."""
    if not version_range.strip():
        return True
    current = _parse_version(version)
    for clause in version_range.split(","):
        clause = clause.strip()
        match = re.match(r"^(>=|<=|==|~=|>|<)?\s*(\d[\d.\-+]*)", clause)
        if not match:
            return False
        operator, target = match.group(1) or "==", _parse_version(match.group(2))
        width = max(len(current), len(target))
        current_padded = current + (0,) * (width - len(current))
        target_padded = target + (0,) * (width - len(target))
        if operator == "==":
            ok = current_padded == target_padded
        elif operator == ">=":
            ok = current_padded >= target_padded
        elif operator == "<=":
            ok = current_padded <= target_padded
        elif operator == ">":
            ok = current_padded > target_padded
        elif operator == "<":
            ok = current_padded < target_padded
        elif operator == "~=":
            prefix = len(target) - 1
            ok = current_padded >= target_padded and current_padded[:prefix] == target_padded[:prefix]
        else:
            return False
        if not ok:
            return False
    return True


def check_tool_health(
    tool_id: str,
    binary: str,
    version_range: str,
    *,
    installed_version: str = "",
    platform: str = "",
    supported_platforms: tuple[str, ...] = (),
) -> ToolHealthReport:
    """Safe presence/version metadata. No execution, no secrets, no env contents.

    shutil.which performs PATH lookup only (never executes). Platform is
    caller-supplied; empty means the gate is skipped, never assumed.
    """
    if supported_platforms and platform:
        if not any(platform == supported or platform.startswith(supported) for supported in supported_platforms):
            return ToolHealthReport(tool_id=tool_id, status=ToolHealth.UNSUPPORTED, installed_version=installed_version, reason=f"platform {platform} not in {sorted(supported_platforms)}")
    if shutil.which(binary) is None:
        return ToolHealthReport(tool_id=tool_id, status=ToolHealth.MISSING, reason=f"executable not found: {binary}")
    if installed_version and not satisfies_range(installed_version, version_range):
        return ToolHealthReport(tool_id=tool_id, status=ToolHealth.VERSION_UNSUPPORTED, installed_version=installed_version, reason=f"version {installed_version} outside {version_range}")
    return ToolHealthReport(tool_id=tool_id, status=ToolHealth.AVAILABLE, installed_version=installed_version, reason="present")


class ToolPackResolver:
    def __init__(self, registry: ToolPackRegistry, *, tool_registry: Any = None):
        self._packs = registry
        self._tools = tool_registry

    def resolve_by_tool(
        self,
        tool_id: str,
        *,
        capability: str = "",
        platform: str = "",
        target_type: str = "repo",
        network_available: bool = False,
        installed_versions: dict[str, str] | None = None,
    ) -> ResolvedTool:
        candidates = self._packs.definitions_for_tool(tool_id)
        if not candidates:
            raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"unknown tool reference: {tool_id}")
        return self._select(candidates, capability=capability, platform=platform, target_type=target_type, network_available=network_available, installed_versions=installed_versions or {})

    def resolve_by_capability(
        self,
        capability: str,
        *,
        platform: str = "",
        target_type: str = "repo",
        network_available: bool = False,
        installed_versions: dict[str, str] | None = None,
    ) -> ResolvedTool:
        """A skill expresses a required capability; the resolver — never the
        skill — chooses the compatible registered implementation."""
        candidates = self._packs.definitions_for_capability(capability)
        if not candidates:
            raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"no registered tool offers capability: {capability}")
        return self._select(candidates, capability=capability, platform=platform, target_type=target_type, network_available=network_available, installed_versions=installed_versions or {})

    def resolve_optional(
        self,
        tool_id: str,
        *,
        capability: str = "",
        platform: str = "",
        target_type: str = "repo",
        network_available: bool = False,
        installed_versions: dict[str, str] | None = None,
    ) -> ResolvedTool:
        """Optional tools degrade explicitly instead of failing the workflow."""
        try:
            return self.resolve_by_tool(tool_id, capability=capability, platform=platform, target_type=target_type, network_available=network_available, installed_versions=installed_versions)
        except ToolPackError as e:
            return ResolvedTool(pack_id="", pack_version="", definition_id="", tool_id=tool_id, capability=capability, health=ToolHealth.MISSING if e.code == ToolPackErrorCode.NOT_FOUND else ToolHealth.BROKEN, degraded=True, reason=str(e))

    def _select(self, candidates: list[tuple[ToolPack, ToolDefinition]], *, capability: str, platform: str, target_type: str, network_available: bool, installed_versions: dict[str, str]) -> ResolvedTool:
        scoped = [c for c in candidates if not capability or capability in c[1].capabilities]
        if not scoped:
            raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"no definition offers capability: {capability or '(any)'}")
        scoped = [c for c in scoped if not target_type or target_type in c[1].supported_targets]
        if not scoped:
            raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"no definition supports target type: {target_type}")
        network_blocked = [c for c in scoped if c[1].network == NetworkRequirement.REQUIRED and not network_available]
        scoped = [c for c in scoped if not (c[1].network == NetworkRequirement.REQUIRED and not network_available)]
        if not scoped:
            raise ToolPackError(ToolPackErrorCode.NETWORK_UNAVAILABLE, f"network-required tools unavailable (deferred: {[c[1].definition_id for c in network_blocked]})")
        for pack, definition in scoped:
            if not definition.executable:
                continue  # declared but deferred mode (e.g. SBOM variant awaiting adapter)
            health = check_tool_health(definition.tool_id, pack.entrypoint, definition.version_range, installed_version=installed_versions.get(definition.tool_id, self._registry_version(definition.tool_id)), platform=platform, supported_platforms=pack.supported_platforms)
            if health.status == ToolHealth.AVAILABLE:
                return ResolvedTool(pack_id=pack.pack_id, pack_version=pack.version, definition_id=definition.definition_id, tool_id=definition.tool_id, capability=capability or (definition.capabilities[0] if definition.capabilities else ""), health=ToolHealth.AVAILABLE, reason=f"{pack.pack_id}@{pack.version}/{definition.definition_id}")
            if health.status == ToolHealth.VERSION_UNSUPPORTED:
                raise ToolPackError(ToolPackErrorCode.VERSION_UNSUPPORTED, f"{definition.tool_id} {health.reason}")
        raise ToolPackError(ToolPackErrorCode.TOOL_UNAVAILABLE, f"no healthy definition (checked {len(scoped)} candidate(s))")

    def _registry_version(self, tool_id: str) -> str:
        if self._tools is None:
            return ""
        try:
            return str(self._tools.get(tool_id).version or "")
        except Exception:
            return ""
