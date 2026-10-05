"""Report template registry — POST-RC-003 (discovery only, no authority)."""

from __future__ import annotations

from emo_cyber_agent.report_templates.spec import ReportTemplateSpec, TemplateError, TemplateErrorCode, TemplateTrust


class ReportTemplateRegistry:
    def __init__(self) -> None:
        self._templates: dict[tuple[str, str], ReportTemplateSpec] = {}
        self._trust: dict[tuple[str, str], TemplateTrust] = {}

    def register(self, spec: ReportTemplateSpec, *, trust: TemplateTrust = TemplateTrust.UNTRUSTED) -> None:
        key = (spec.template_id, spec.version)
        if key in self._templates:
            raise TemplateError(TemplateErrorCode.INVALID, f"duplicate template: {spec.template_id}@{spec.version}")
        self._templates[key] = spec
        self._trust[key] = trust

    def unregister(self, template_id: str, version: str) -> None:
        key = (template_id, version)
        if key not in self._templates:
            raise TemplateError(TemplateErrorCode.NOT_FOUND, f"template not registered: {template_id}@{version}")
        dependents = [f"{tid}@{ver}" for (tid, ver), spec in self._templates.items() if spec.extends == template_id and (tid, ver) != key]
        if dependents:
            raise TemplateError(TemplateErrorCode.INVALID, f"template extended by: {sorted(dependents)}")
        del self._templates[key]
        del self._trust[key]

    def get(self, template_id: str, version: str | None = None) -> ReportTemplateSpec:
        if version is not None:
            try:
                return self._templates[(template_id, version)]
            except KeyError:
                raise TemplateError(TemplateErrorCode.NOT_FOUND, f"template not registered: {template_id}@{version}") from None
        candidates = sorted(ver for (tid, ver) in self._templates if tid == template_id)
        if not candidates:
            raise TemplateError(TemplateErrorCode.NOT_FOUND, f"template not registered: {template_id}")
        return self._templates[(template_id, candidates[-1])]

    def list(self) -> list[ReportTemplateSpec]:
        return [self._templates[key] for key in sorted(self._templates)]

    def versions(self, template_id: str) -> list[str]:
        return sorted(ver for (tid, ver) in self._templates if tid == template_id)

    def trust_of(self, template_id: str, version: str) -> TemplateTrust:
        try:
            return self._trust[(template_id, version)]
        except KeyError:
            raise TemplateError(TemplateErrorCode.NOT_FOUND, f"template not registered: {template_id}@{version}") from None

    def check_cycles(self) -> list[str]:
        cycles: list[str] = []
        visited: dict[str, str] = {}

        def visit(node: str, stack: list[str]) -> None:
            visited[node] = "open"
            stack.append(node)
            try:
                parent = self.get(node).extends
            except TemplateError:
                parent = None
            deps = [parent] if parent else []
            for dep in sorted(deps):
                if dep not in visited:
                    visit(dep, stack)
                elif visited[dep] == "open":
                    cycles.append("->".join([*stack[stack.index(dep):], dep]))
            stack.pop()
            visited[node] = "closed"

        for tid in sorted({tid for (tid, _v) in self._templates}):
            if tid not in visited:
                visit(tid, [])
        return sorted(cycles)
