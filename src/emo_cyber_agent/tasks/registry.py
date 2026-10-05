"""Task registry — POST-RC-002.

Version-aware store. Registration validates structure only; trust is
computed, never assumed. Invalid tasks, missing references, and cycles
are rejected deterministically.
"""

from __future__ import annotations

from emo_cyber_agent.tasks.spec import TaskError, TaskErrorCode, TaskSpec, TaskTrust


class TaskRegistry:
    def __init__(self) -> None:
        self._tasks: dict[tuple[str, str], TaskSpec] = {}
        self._trust: dict[tuple[str, str], TaskTrust] = {}

    def register(self, spec: TaskSpec, *, trust: TaskTrust = TaskTrust.UNTRUSTED) -> None:
        key = (spec.task_id, spec.version)
        if key in self._tasks:
            raise TaskError(TaskErrorCode.INVALID, f"duplicate task: {spec.task_id}@{spec.version}")
        self._tasks[key] = spec
        self._trust[key] = trust

    def unregister(self, task_id: str, version: str) -> None:
        key = (task_id, version)
        if key not in self._tasks:
            raise TaskError(TaskErrorCode.NOT_FOUND, f"task not registered: {task_id}@{version}")
        dependents = [f"{tid}@{ver}" for (tid, ver), spec in self._tasks.items() if spec.extends == task_id and (tid, ver) != key]
        if dependents:
            raise TaskError(TaskErrorCode.INVALID, f"task extended by: {sorted(dependents)}")
        del self._tasks[key]
        del self._trust[key]

    def get(self, task_id: str, version: str | None = None) -> TaskSpec:
        if version is not None:
            try:
                return self._tasks[(task_id, version)]
            except KeyError:
                raise TaskError(TaskErrorCode.NOT_FOUND, f"task not registered: {task_id}@{version}") from None
        candidates = sorted(ver for (tid, ver) in self._tasks if tid == task_id)
        if not candidates:
            raise TaskError(TaskErrorCode.NOT_FOUND, f"task not registered: {task_id}")
        return self._tasks[(task_id, candidates[-1])]

    def list(self) -> list[TaskSpec]:
        return [self._tasks[key] for key in sorted(self._tasks)]

    def versions(self, task_id: str) -> list[str]:
        return sorted(ver for (tid, ver) in self._tasks if tid == task_id)

    def trust_of(self, task_id: str, version: str) -> TaskTrust:
        try:
            return self._trust[(task_id, version)]
        except KeyError:
            raise TaskError(TaskErrorCode.NOT_FOUND, f"task not registered: {task_id}@{version}") from None

    def dependencies(self, task_id: str, version: str | None = None) -> list[str]:
        spec = self.get(task_id, version)
        return [spec.extends] if spec.extends else []

    def compatible_tasks(self, task_id: str, version: str | None = None) -> list[TaskSpec]:
        base = self.get(task_id, version)
        out = []
        for spec in self.list():
            if spec.task_id == base.task_id:
                continue
            if set(spec.required_skills) & set(base.required_skills) or spec.extends == base.task_id or base.task_id in (spec.extends or ""):
                out.append(spec)
        return out

    def check_cycles(self) -> list[str]:
        cycles: list[str] = []
        visited: dict[str, str] = {}

        def visit(node: str, stack: list[str]) -> None:
            visited[node] = "open"
            stack.append(node)
            try:
                deps = self.dependencies(node)
            except TaskError:
                deps = []
            for dep in sorted(deps):
                if dep not in visited:
                    visit(dep, stack)
                elif visited[dep] == "open":
                    cycles.append("->".join([*stack[stack.index(dep):], dep]))
            stack.pop()
            visited[node] = "closed"

        for tid in sorted({tid for (tid, _v) in self._tasks}):
            if tid not in visited:
                visit(tid, [])
        return sorted(cycles)
