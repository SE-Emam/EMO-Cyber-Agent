"""Tool pack registry — POST-RC-007 (discovery only, no authority)."""

from __future__ import annotations

from emo_cyber_agent.tools.packs.errors import ToolPackError, ToolPackErrorCode
from emo_cyber_agent.tools.packs.spec import PackTrust, ToolDefinition, ToolPack


class ToolPackRegistry:
    def __init__(self) -> None:
        self._packs: dict[tuple[str, str], ToolPack] = {}
        self._trust: dict[tuple[str, str], PackTrust] = {}

    def register(self, pack: ToolPack, *, trust: PackTrust = PackTrust.UNTRUSTED) -> None:
        key = (pack.pack_id, pack.version)
        if key in self._packs:
            raise ToolPackError(ToolPackErrorCode.DUPLICATE, f"duplicate pack: {pack.pack_id}@{pack.version}")
        self._packs[key] = pack
        self._trust[key] = trust

    def unregister(self, pack_id: str, version: str) -> None:
        key = (pack_id, version)
        if key not in self._packs:
            raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"pack not registered: {pack_id}@{version}")
        del self._packs[key]
        del self._trust[key]

    def get(self, pack_id: str, version: str | None = None) -> ToolPack:
        if version is not None:
            try:
                return self._packs[(pack_id, version)]
            except KeyError:
                raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"pack not registered: {pack_id}@{version}") from None
        candidates = sorted(ver for (pid, ver) in self._packs if pid == pack_id)
        if not candidates:
            raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"pack not registered: {pack_id}")
        return self._packs[(pack_id, candidates[-1])]

    def list(self) -> list[ToolPack]:
        return [self._packs[key] for key in sorted(self._packs)]

    def versions(self, pack_id: str) -> list[str]:
        return sorted(ver for (pid, ver) in self._packs if pid == pack_id)

    def trust_of(self, pack_id: str, version: str) -> PackTrust:
        try:
            return self._trust[(pack_id, version)]
        except KeyError:
            raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"pack not registered: {pack_id}@{version}") from None

    def definitions_for_tool(self, tool_id: str) -> list[tuple[ToolPack, ToolDefinition]]:
        """All definitions driving one tool_id, deterministic order."""
        out = []
        for pack in self.list():
            for definition in pack.definitions:
                if definition.tool_id == tool_id:
                    out.append((pack, definition))
        return out

    def definitions_for_capability(self, capability: str) -> list[tuple[ToolPack, ToolDefinition]]:
        """All definitions offering one pack capability, deterministic order."""
        out = []
        for pack in self.list():
            for definition in pack.definitions:
                if capability in definition.capabilities:
                    out.append((pack, definition))
        return out
