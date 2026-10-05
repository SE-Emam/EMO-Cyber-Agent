"""Playbook resolver — POST-RC-004 (deterministic, no LLM, no execution).

PlaybookSpec + ProjectContext → immutable ResolvedPlaybook snapshot.
Delegates every resolution decision to the owning system:
TaskResolver (tasks), SkillResolver (skills), ToolRegistry (tools),
ReportTemplateResolver (report template). This module only
ORCHESTRATES: condition evaluation, ordering, aggregation, safety
rechecks, snapshot freezing.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.playbooks.spec import (
    PlaybookCondition,
    PlaybookError,
    PlaybookErrorCode,
    PlaybookPlan,
    PlaybookSpec,
    PlaybookStatus,
    ProjectContext,
    ResolvedPlaybook,
    ResolvedPlaybookTask,
    ResolutionStatus,
    is_write_capability,
    task_ref_id,
    task_ref_version,
)


def evaluate_condition(condition: PlaybookCondition, context: ProjectContext) -> tuple[bool, str]:
    """Evaluate one declarative condition against context sets.

    Empty/unknown context selects NOTHING (fail-closed). Returns
    (matched, reason). Unknown operator value shapes → no match.
    """
    actual: tuple[str, ...] = ()
    if condition.when_field == "technology":
        actual = context.technologies
    elif condition.when_field == "asset.type":
        actual = context.asset_types
    elif condition.when_field == "evidence.category":
        actual = context.evidence_categories
    elif condition.when_field == "candidate.status":
        actual = context.candidate_statuses
    else:
        return False, f"condition-unknown-field:{condition.when_field}"
    if not actual:
        return False, f"condition-no-context:{condition.when_field}"
    value = condition.value
    op = condition.operator
    lowered = tuple(a.lower() for a in actual)
    if op == "==":
        matched = str(value).lower() in lowered
    elif op == "!=":
        matched = str(value).lower() not in lowered
    elif op == "in":
        choices = [str(v).lower() for v in (value if isinstance(value, list) else [value])]
        matched = any(c in lowered for c in choices)
    elif op == "not-in":
        choices = [str(v).lower() for v in (value if isinstance(value, list) else [value])]
        matched = not any(c in lowered for c in choices)
    else:
        return False, f"condition-unknown-operator:{op}"
    return matched, f"condition-{condition.when_field}-{op}-{'matched' if matched else 'no-match'}"


class PlaybookResolver:
    def __init__(self, *, task_registry: Any = None, skill_registry: Any = None, tool_registry: Any = None, template_registry: Any = None, policy_version: str = ""):
        self._tasks = task_registry
        self._skills = skill_registry
        self._tools = tool_registry
        self._templates = template_registry
        self._policy_version = policy_version

    def resolve(
        self,
        spec: PlaybookSpec,
        *,
        project_files: list[str],
        project_objective: str = "",
        audit_scope: Any = None,
        context: ProjectContext | None = None,
        skill_versions: dict[str, str] | None = None,
    ) -> ResolvedPlaybook:
        from emo_cyber_agent.tasks.resolver import TaskResolver

        reasons: list[str] = []
        warnings: list[str] = []
        context = context or ProjectContext()
        skill_versions = skill_versions or {}
        task_resolver = TaskResolver(skill_registry=self._skills, tool_registry=self._tools, template_registry=self._templates, policy_version=self._policy_version)

        # --- 1. condition evaluation (declarative selection only) ---
        selected_conditional: list[str] = []
        conditions_evaluated: list[str] = []
        if spec.conditions and not any([context.technologies, context.asset_types, context.evidence_categories, context.candidate_statuses]):
            warnings.append("conditions-no-context:no-selection")
        for cond in spec.conditions:
            matched, reason = evaluate_condition(cond, context)
            conditions_evaluated.append(reason)
            if matched:
                for ref in cond.select_tasks:
                    tid = task_ref_id(ref)
                    if tid not in selected_conditional:
                        selected_conditional.append(tid)
                reasons.append(f"condition-selected:{sorted(cond.select_tasks)}")
            else:
                reasons.append(f"condition-skipped:{cond.when_field}")

        # --- 2. task set: required always; optional only when selected ---
        required_ids = [task_ref_id(r) for r in spec.required_tasks]
        optional_ids = [task_ref_id(r) for r in spec.optional_tasks]
        activated_optional = [t for t in selected_conditional if t in optional_ids]
        for t in selected_conditional:
            if t not in required_ids and t not in optional_ids:
                raise PlaybookError(PlaybookErrorCode.CONDITION_INVALID, f"condition selects undeclared task: {t}")
        planned_ids = [*required_ids, *activated_optional]
        skipped_conditionals = [t for t in optional_ids if t not in activated_optional]

        # --- 3. ordering: execution_order first, then declaration order ---
        ordered: list[str] = []
        if spec.execution_order:
            for tid in spec.execution_order:
                if tid in planned_ids and tid not in ordered:
                    ordered.append(tid)
            for tid in planned_ids:
                if tid not in ordered:
                    ordered.append(tid)
                    warnings.append(f"order-unlisted:{tid}")
        else:
            ordered = list(planned_ids)

        # --- 4. budget: closest/strictest wins → exceed means BLOCKED ---
        if len(ordered) > spec.max_tasks:
            return self._blocked(spec, reasons + [f"budget-exceeded:max_tasks={spec.max_tasks}"], warnings, context)

        # --- 5. resolve tasks via owning TaskResolver (scope enforced there) ---
        resolved_tasks: list[ResolvedPlaybookTask] = []
        skipped_optional: list[str] = []
        evidence: list[str] = list(spec.evidence_required)
        verification_methods: list[str] = list(spec.verification_methods)
        task_caps: list[str] = []
        task_denied: list[str] = []
        for tid in ordered:
            is_required = tid in required_ids
            ref = next((r for r in (*spec.required_tasks, *spec.optional_tasks) if task_ref_id(r) == tid), tid)
            try:
                if self._tasks is None:
                    raise PlaybookError(PlaybookErrorCode.TASK_MISSING, f"no task registry wired: {tid}")
                task_spec = self._tasks.get(tid, task_ref_version(ref))
            except PlaybookError:
                raise
            except Exception:
                if is_required:
                    return self._blocked(spec, reasons + [f"required-task-missing:{tid}"], warnings, context)
                skipped_optional.append(tid)
                warnings.append(f"optional-task-missing:{tid}")
                continue
            try:
                rt = task_resolver.resolve(task_spec, project_files=project_files, project_objective=project_objective, audit_scope=audit_scope, skill_versions=skill_versions)
            except Exception as e:
                if is_required:
                    return self._blocked(spec, reasons + [f"required-task-failed:{tid}:{e}"], warnings, context)
                skipped_optional.append(tid)
                warnings.append(f"optional-task-failed:{tid}")
                continue
            selected_by = "required" if is_required else "condition"
            resolved_tasks.append(ResolvedPlaybookTask(task_id=rt.task_id, task_version=rt.task_version, pinned_ref=f"{rt.task_id}@{rt.task_version}", status=str(rt.status), selected_by=selected_by, skill_versions=dict(rt.skill_versions), tool_versions=dict(rt.tool_versions)))
            reasons.append(f"task:{tid}@{rt.task_version} ({selected_by})")
            evidence.extend([e for e in rt.evidence_requirements if e not in evidence])
            verification_methods.extend([m for m in rt.verification_methods if m not in verification_methods])
            task_caps.extend([c for c in (*rt.requested_capabilities,)])
            task_denied.extend([c for c in rt.denied_capabilities])

        # --- 6. skills via owning SkillResolver (never reimplemented) ---
        skills_matched: list[str] = []
        if self._skills is not None:
            from emo_cyber_agent.skills.resolver import SkillResolver as _SkillResolver

            matches = _SkillResolver(self._skills).resolve(files=project_files, objective=project_objective)
            by_id = {m["skill_id"]: m for m in matches}
            for sid in sorted(set(spec.required_skills)):
                if sid in by_id:
                    skills_matched.append(sid)
                    reasons.append(f"skill:{sid} matched project signals")
                else:
                    return self._blocked(spec, reasons + [f"required-skill-unmatched:{sid}"], warnings, context)
            for sid in sorted(set(spec.optional_skills)):
                if sid in by_id:
                    skills_matched.append(sid)
                else:
                    warnings.append(f"optional-skill-unmatched:{sid}")
            try:
                skill_caps = _SkillResolver(self._skills).required_capabilities(skills_matched)
            except Exception:
                skill_caps = []
        else:
            skills_matched = sorted(set(spec.required_skills) | set(spec.optional_skills))
            skill_caps = []
            if skills_matched:
                warnings.append("skills-unverified:no-registry")

        # --- 7. tools: names must resolve when a registry is wired ---
        requested_tools: list[str] = []
        tool_versions: dict[str, str] = {}
        for tool in sorted(set(spec.required_tools)):
            if self._tools is not None:
                try:
                    resolved_tool = self._tools.get(tool)
                    requested_tools.append(tool)
                    tool_versions[tool] = str(getattr(resolved_tool, "version", "unknown"))
                except Exception:
                    return self._blocked(spec, reasons + [f"required-tool-missing:{tool}"], warnings, context)
            else:
                requested_tools.append(tool)
                warnings.append(f"tool-unverified:{tool}")
        for tool in sorted(set(spec.optional_tools)):
            if self._tools is not None:
                try:
                    resolved_tool = self._tools.get(tool)
                    requested_tools.append(tool)
                    tool_versions[tool] = str(getattr(resolved_tool, "version", "unknown"))
                except Exception:
                    warnings.append(f"optional-tool-absent:{tool}")
            else:
                requested_tools.append(tool)

        # --- 8. capabilities: advisory union; denied unions (parent dominates) ---
        requested_caps = sorted(set(spec.requested_capabilities) | set(task_caps) | set(skill_caps or []))
        denied_caps = sorted(set(spec.denied_capabilities) | set(task_denied))
        if requested_caps:
            warnings.append("capabilities-advisory-only: Core PolicyEngine decides")

        # --- 9. read-only recheck (covers registry drift past validation) ---
        if spec.security_read_only_default:
            offending = sorted({c for c in requested_caps if is_write_capability(c)})
            if offending:
                return self._blocked(spec, reasons + [f"read-only-violation:{offending[0]}"], warnings, context)

        # --- 10. report template snapshot via owning resolver ---
        template_version = ""
        template_known = False
        if self._templates is not None and spec.report_template:
            from emo_cyber_agent.report_templates.resolver import ReportTemplateResolver as _TplResolver

            try:
                snap = _TplResolver(self._templates).resolve(template_id=spec.report_template)
                template_version = snap.version
                template_known = True
                reasons.append(f"report-template:{spec.report_template}@{template_version}")
            except Exception:
                return self._blocked(spec, reasons + [f"template-missing:{spec.report_template}"], warnings, context)
        elif spec.report_template:
            warnings.append(f"template-unverified:{spec.report_template}")

        # --- 11. plan + snapshot ---
        skill_version_map: dict[str, str] = {}
        for t in resolved_tasks:
            skill_version_map.update(t.skill_versions)
        for sid in skills_matched:
            skill_version_map.setdefault(sid, skill_versions.get(sid, "unknown"))
        plan = PlaybookPlan(
            playbook_id=spec.playbook_id, playbook_version=spec.version, ordered_task_ids=tuple(ordered),
            skipped_tasks=tuple(sorted([*skipped_optional, *skipped_conditionals])), conditions_evaluated=tuple(conditions_evaluated),
            constraints=tuple(sorted([f"deny:{c}" for c in denied_caps] + (["read-only"] if spec.security_read_only_default else []))),
            expected_evidence=tuple(sorted(set(evidence))), stop_rules=tuple(spec.stop_conditions), report_template=spec.report_template,
        )
        payload = {"playbook": [spec.playbook_id, spec.version], "tasks": [[t.task_id, t.task_version] for t in resolved_tasks], "skills": sorted(skills_matched), "tools": sorted(requested_tools), "caps": requested_caps, "plan": list(ordered), "template": [spec.report_template, template_version]}
        from emo_cyber_agent.playbooks.spec import ResolvedPlaybook as _RP

        digest = _RP.digest_of(payload)
        status = ResolutionStatus.PARTIAL if (skipped_optional or warnings) else ResolutionStatus.RESOLVED
        return ResolvedPlaybook(
            playbook_id=spec.playbook_id, playbook_version=spec.version, status=status, tasks=tuple(resolved_tasks),
            skipped_optional_tasks=tuple(sorted(skipped_optional)), skills=tuple(sorted(skills_matched)), skill_versions=skill_version_map,
            requested_tools=tuple(sorted(requested_tools)), tool_versions=tool_versions, requested_capabilities=tuple(requested_caps),
            denied_capabilities=tuple(denied_caps), evidence_requirements=tuple(sorted(set(evidence))),
            verification_requirements=tuple([f"required={spec.verification_required}"]), verification_methods=tuple(sorted(set(verification_methods))),
            report_template=spec.report_template, report_template_version=template_version, report_template_known=template_known,
            plan=plan, lifecycle=PlaybookStatus.READY, policy_version=self._policy_version, digest=digest,
            reasons=tuple(reasons), warnings=tuple(warnings),
        )

    def _blocked(self, spec: PlaybookSpec, reasons: list[str], warnings: list[str], _context: ProjectContext) -> ResolvedPlaybook:
        return ResolvedPlaybook(
            playbook_id=spec.playbook_id, playbook_version=spec.version, status=ResolutionStatus.BLOCKED,
            lifecycle=PlaybookStatus.BLOCKED, policy_version=self._policy_version, reasons=tuple(reasons), warnings=tuple(warnings),
        )
