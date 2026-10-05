"""Task service — POST-RC-002 application facade.

validate → resolve → snapshot. No execution, no subprocess, no scanner,
no model. The returned ResolvedTask is immutable; later registry mutation
cannot alter an in-flight audit.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.tasks.resolver import TaskResolver
from emo_cyber_agent.tasks.spec import ResolvedTask, TaskScope
from emo_cyber_agent.tasks.validator import TaskValidator


class TaskService:
    def __init__(self, *, task_registry: Any, skill_registry: Any = None, tool_registry: Any = None, template_registry: Any = None, policy_version: str = ""):
        self._tasks = task_registry
        self._validator = TaskValidator(skill_registry=skill_registry, tool_registry=tool_registry)
        self._resolver = TaskResolver(skill_registry=skill_registry, tool_registry=tool_registry, template_registry=template_registry, policy_version=policy_version)

    @property
    def validator(self) -> TaskValidator:
        return self._validator

    def plan(
        self,
        task_id: str,
        *,
        version: str | None = None,
        project_files: list[str] | None = None,
        project_objective: str = "",
        audit_scope: TaskScope | None = None,
        report_template_override: str | None = None,
    ) -> ResolvedTask:
        spec = self._tasks.get(task_id, version)
        validation = self._validator.validate(spec)
        if not validation.valid:
            from emo_cyber_agent.tasks.spec import ResolutionStatus

            return ResolvedTask(task_id=spec.task_id, task_version=spec.version, status=ResolutionStatus.INVALID, reasons=tuple(validation.errors), warnings=tuple(validation.warnings))
        return self._resolver.resolve(spec, project_files=project_files or [], project_objective=project_objective, audit_scope=audit_scope, report_template_override=report_template_override)
