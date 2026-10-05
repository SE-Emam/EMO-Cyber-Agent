"""Playbook registry — POST-RC-004 (discovery only, no authority)."""

from __future__ import annotations

from emo_cyber_agent.playbooks.spec import PlaybookError, PlaybookErrorCode, PlaybookSpec, PlaybookTrust


class PlaybookRegistry:
    def __init__(self) -> None:
        self._playbooks: dict[tuple[str, str], PlaybookSpec] = {}
        self._trust: dict[tuple[str, str], PlaybookTrust] = {}

    def register(self, spec: PlaybookSpec, *, trust: PlaybookTrust = PlaybookTrust.UNTRUSTED) -> None:
        key = (spec.playbook_id, spec.version)
        if key in self._playbooks:
            raise PlaybookError(PlaybookErrorCode.INVALID, f"duplicate playbook: {spec.playbook_id}@{spec.version}")
        self._playbooks[key] = spec
        self._trust[key] = trust

    def unregister(self, playbook_id: str, version: str) -> None:
        key = (playbook_id, version)
        if key not in self._playbooks:
            raise PlaybookError(PlaybookErrorCode.NOT_FOUND, f"playbook not registered: {playbook_id}@{version}")
        dependents = [f"{pid}@{ver}" for (pid, ver), spec in self._playbooks.items() if (spec.extends == playbook_id or playbook_id in spec.dependencies) and (pid, ver) != key]
        if dependents:
            raise PlaybookError(PlaybookErrorCode.INVALID, f"playbook depended on by: {sorted(dependents)}")
        del self._playbooks[key]
        del self._trust[key]

    def get(self, playbook_id: str, version: str | None = None) -> PlaybookSpec:
        if version is not None:
            try:
                return self._playbooks[(playbook_id, version)]
            except KeyError:
                raise PlaybookError(PlaybookErrorCode.NOT_FOUND, f"playbook not registered: {playbook_id}@{version}") from None
        candidates = sorted(ver for (pid, ver) in self._playbooks if pid == playbook_id)
        if not candidates:
            raise PlaybookError(PlaybookErrorCode.NOT_FOUND, f"playbook not registered: {playbook_id}")
        return self._playbooks[(playbook_id, candidates[-1])]

    def list(self) -> list[PlaybookSpec]:
        return [self._playbooks[key] for key in sorted(self._playbooks)]

    def versions(self, playbook_id: str) -> list[str]:
        return sorted(ver for (pid, ver) in self._playbooks if pid == playbook_id)

    def trust_of(self, playbook_id: str, version: str) -> PlaybookTrust:
        try:
            return self._trust[(playbook_id, version)]
        except KeyError:
            raise PlaybookError(PlaybookErrorCode.NOT_FOUND, f"playbook not registered: {playbook_id}@{version}") from None

    def dependencies(self, playbook_id: str, version: str | None = None) -> list[str]:
        spec = self.get(playbook_id, version)
        deps = list(spec.dependencies)
        if spec.extends and spec.extends not in deps:
            deps.append(spec.extends)
        return sorted(deps)

    def check_cycles(self) -> list[str]:
        cycles: list[str] = []
        visited: dict[str, str] = {}

        def visit(node: str, stack: list[str]) -> None:
            visited[node] = "open"
            stack.append(node)
            try:
                deps = self.dependencies(node)
            except PlaybookError:
                deps = []
            for dep in sorted(deps):
                if dep not in visited:
                    visit(dep, stack)
                elif visited[dep] == "open":
                    cycles.append("->".join([*stack[stack.index(dep):], dep]))
            stack.pop()
            visited[node] = "closed"

        for pid in sorted({pid for (pid, _v) in self._playbooks}):
            if pid not in visited:
                visit(pid, [])
        return sorted(cycles)
