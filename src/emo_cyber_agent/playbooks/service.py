"""Playbook service — POST-RC-004 application facade.

validate → resolve → snapshot. No execution, no subprocess, no scanner,
no model. The returned ResolvedPlaybook is immutable; later registry
mutation cannot alter an in-flight audit.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.playbooks.registry import PlaybookRegistry
from emo_cyber_agent.playbooks.resolver import PlaybookResolver
from emo_cyber_agent.playbooks.spec import ProjectContext, ResolvedPlaybook, ResolutionStatus
from emo_cyber_agent.playbooks.validator import PlaybookValidator


class PlaybookService:
    def __init__(self, registry: PlaybookRegistry, *, task_registry: Any = None, skill_registry: Any = None, tool_registry: Any = None, template_registry: Any = None, policy_version: str = ""):
        self._registry = registry
        self._validator = PlaybookValidator(task_registry=task_registry, skill_registry=skill_registry, tool_registry=tool_registry, template_registry=template_registry)
        self._resolver = PlaybookResolver(task_registry=task_registry, skill_registry=skill_registry, tool_registry=tool_registry, template_registry=template_registry, policy_version=policy_version)

    def _apply_inheritance(self, spec: Any) -> Any:
        """Parent constraints dominate: union denied caps, stop rules, and
        forbidden actions down the extends chain. A child can add, never
        remove. Missing parent → INVALID at plan time (returned as spec
        with a marker the validator rejects via extends shape? no — raise
        into an INVALID snapshot by the caller)."""
        seen: set[str] = {spec.playbook_id}
        merged_denied = list(spec.denied_capabilities)
        merged_stops = list(spec.stop_conditions)
        merged_forbidden = list(spec.security_forbidden_actions)
        merged_required = list(spec.required_tasks)
        parent_id = spec.extends
        while parent_id:
            if parent_id in seen:
                raise ValueError(f"extends-cycle:{parent_id}")
            seen.add(parent_id)
            try:
                parent = self._registry.get(parent_id)
            except Exception as e:
                raise ValueError(f"extends-missing:{parent_id}") from e
            for cap in parent.denied_capabilities:
                if cap not in merged_denied:
                    merged_denied.append(cap)
            for stop in parent.stop_conditions:
                if stop not in merged_stops:
                    merged_stops.append(stop)
            for action in parent.security_forbidden_actions:
                if action not in merged_forbidden:
                    merged_forbidden.append(action)
            for ref in parent.required_tasks:
                if ref not in merged_required:
                    merged_required.append(ref)
            parent_id = parent.extends
        if parent_id is None and spec.extends is None:
            return spec
        return spec.model_copy(update={"denied_capabilities": tuple(merged_denied), "stop_conditions": tuple(merged_stops), "security_forbidden_actions": tuple(merged_forbidden), "required_tasks": tuple(merged_required)})

    @property
    def validator(self) -> PlaybookValidator:
        return self._validator

    @property
    def resolver(self) -> PlaybookResolver:
        return self._resolver

    def plan(
        self,
        playbook_id: str,
        *,
        version: str | None = None,
        project_files: list[str] | None = None,
        project_objective: str = "",
        audit_scope: Any = None,
        context: ProjectContext | None = None,
        skill_versions: dict[str, str] | None = None,
    ) -> ResolvedPlaybook:
        try:
            spec = self._registry.get(playbook_id, version)
        except Exception as e:
            return ResolvedPlaybook(playbook_id=playbook_id, playbook_version=version or "", status=ResolutionStatus.INVALID, reasons=(str(e),))
        try:
            spec = self._apply_inheritance(spec)
        except ValueError as e:
            return ResolvedPlaybook(playbook_id=playbook_id, playbook_version=version or "", status=ResolutionStatus.INVALID, reasons=(str(e),))
        validation = self._validator.validate(spec)
        if not validation.valid:
            return ResolvedPlaybook(playbook_id=spec.playbook_id, playbook_version=spec.version, status=ResolutionStatus.INVALID, reasons=tuple(validation.errors), warnings=tuple(validation.warnings))
        resolved = self._resolver.resolve(spec, project_files=project_files or [], project_objective=project_objective, audit_scope=audit_scope, context=context, skill_versions=skill_versions)
        if validation.warnings and resolved.status == ResolutionStatus.RESOLVED:
            resolved = resolved.model_copy(update={"status": ResolutionStatus.PARTIAL, "warnings": tuple([*resolved.warnings, *validation.warnings])})
        elif validation.warnings:
            resolved = resolved.model_copy(update={"warnings": tuple([*resolved.warnings, *validation.warnings])})
        return resolved
