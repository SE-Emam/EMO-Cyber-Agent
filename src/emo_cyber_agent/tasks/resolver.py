"""Task resolver — POST-RC-002.

TaskSpec + project context → immutable ResolvedTask snapshot. Computes
requirements (skills via POST-RC-001 SkillResolver, tools, capabilities,
evidence, verification, report reference) with per-item reasons. Advisory
only: grants nothing, widens nothing, executes nothing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from emo_cyber_agent.tasks.spec import (
    ResolvedSkill,
    ResolvedTask,
    ResolutionStatus,
    TaskError,
    TaskErrorCode,
    TaskScope,
    TaskSpec,
)


class TaskResolver:
    def __init__(self, *, skill_registry: Any = None, tool_registry: Any = None, template_registry: Any = None, policy_version: str = ""):
        self._skills = skill_registry
        self._tools = tool_registry
        self._templates = template_registry
        self._policy_version = policy_version

    def resolve(
        self,
        spec: TaskSpec,
        *,
        project_files: list[str],
        project_objective: str = "",
        audit_scope: TaskScope | None = None,
        skill_versions: dict[str, str] | None = None,
        report_template_override: str | None = None,
    ) -> ResolvedTask:
        reasons: list[str] = []
        warnings: list[str] = []
        # scope narrowing (task may only narrow audit scope, never widen)
        scope = spec.scope
        if audit_scope is not None and not scope.narrowed_by(audit_scope):
            raise TaskError(TaskErrorCode.SCOPE_INVALID, "task scope exceeds audit scope")
        # skills via POST-RC-001 resolver (never reimplemented here)
        resolved_skills: list[ResolvedSkill] = []
        skipped: list[str] = []
        skill_versions = skill_versions or {}
        if self._skills is not None:
            from emo_cyber_agent.skills.resolver import SkillResolver as _SkillResolver

            matches = _SkillResolver(self._skills).resolve(files=project_files, objective=project_objective)
            by_id = {m["skill_id"]: m for m in matches}
            for sid in sorted(set(spec.required_skills)):
                if sid in by_id:
                    resolved_skills.append(ResolvedSkill(skill_id=sid, version=skill_versions.get(sid, by_id[sid]["version"]), reason=by_id[sid]["reason"]))
                    reasons.append(f"skill:{sid} matched project signals")
                else:
                    raise TaskError(TaskErrorCode.SKILL_MISSING, f"required skill not matched: {sid}")
            for sid in sorted(set(spec.optional_skills)):
                if sid in by_id:
                    resolved_skills.append(ResolvedSkill(skill_id=sid, version=skill_versions.get(sid, by_id[sid]["version"]), reason=by_id[sid]["reason"]))
                    reasons.append(f"optional skill:{sid} matched")
                else:
                    skipped.append(sid)
                    reasons.append(f"optional skill:{sid} unmatched, skipped")
        else:
            for sid in sorted(set(spec.required_skills)):
                resolved_skills.append(ResolvedSkill(skill_id=sid, version=skill_versions.get(sid, "unknown"), reason="no skill registry wired; declared as-is"))
                warnings.append(f"skill-unverified:{sid}")
        # tools: names must resolve when a registry is wired
        requested_tools: list[str] = []
        tool_versions: dict[str, str] = {}
        for tool in sorted(set(spec.required_tools) | set(spec.optional_tools)):
            if self._tools is not None:
                try:
                    resolved = self._tools.get(tool)
                    requested_tools.append(tool)
                    tool_versions[tool] = getattr(resolved, "version", "unknown")
                    reasons.append(f"tool:{tool} resolved in registry")
                except (ValueError, KeyError, AttributeError):
                    if tool in spec.required_tools:
                        raise TaskError(TaskErrorCode.TOOL_MISSING, f"required tool not registered: {tool}") from None
                    skipped.append(tool)
                    reasons.append(f"optional tool:{tool} absent, skipped")
            else:
                requested_tools.append(tool)
                warnings.append(f"tool-unverified:{tool}")
        # capabilities stay advisory: union of skill requests + task declarations
        requested_caps: list[str] = []
        if self._skills is not None:
            from emo_cyber_agent.skills.resolver import SkillResolver as _SkillResolver2

            requested_caps = _SkillResolver2(self._skills).required_capabilities([s.skill_id for s in resolved_skills])
        requested_caps = sorted(set(requested_caps) | set(spec.required_capabilities))
        if requested_caps:
            warnings.append("capabilities-advisory-only: Core PolicyEngine decides")
        # composition: extends target must resolve; child constraints dominate (checked by validator + narrowed scope above)
        if spec.extends:
            reasons.append(f"extends:{spec.extends}")
        # report template: optional override wins, registry verifies existence only.
        effective_template = report_template_override or spec.report_template
        template_known = False
        template_version = ""
        if self._templates is not None and effective_template:
            try:
                resolved_template = self._templates.get(effective_template)
                template_known = True
                template_version = str(getattr(resolved_template, "version", ""))
                reasons.append(f"report-template:{effective_template}@{template_version} known")
            except Exception:
                if report_template_override:
                    raise TaskError(TaskErrorCode.TEMPLATE_MISSING, f"report template override not registered: {report_template_override}") from None
                warnings.append(f"report-template-unverified:{effective_template}")
        elif effective_template:
            warnings.append(f"report-template-unverified:{effective_template}")
        stamp = datetime.now(timezone.utc).isoformat()
        skill_version_map = {s.skill_id: s.version for s in resolved_skills}
        return ResolvedTask(
            task_id=spec.task_id,
            task_version=spec.version,
            status=ResolutionStatus.PARTIAL if (skipped or warnings) else ResolutionStatus.RESOLVED,
            skills=tuple(resolved_skills),
            skipped_optional_skills=tuple(sorted(skipped)),
            requested_tools=tuple(requested_tools),
            requested_capabilities=tuple(requested_caps),
            denied_capabilities=tuple(spec.denied_capabilities),
            scope=scope,
            methodology_phases=tuple(spec.methodology_phases),
            evidence_requirements=tuple(spec.evidence_required),
            verification_requirements=tuple([f"required={spec.verification_required}", f"confirmation={spec.verification_confirmation}", f"refutation={spec.verification_refutation}"]),
            verification_methods=tuple(spec.verification_methods),
            report_template=effective_template,
            report_template_known=template_known,
            stop_conditions=tuple(spec.stop_conditions),
            acceptance_criteria=tuple(spec.acceptance_criteria),
            skill_versions=skill_version_map,
            tool_versions=tool_versions,
            report_template_version=template_version,
            policy_version=self._policy_version,
            resolved_at=stamp,
            reasons=tuple(reasons),
            warnings=tuple(warnings),
        )

    def suggest(self, specs: list[TaskSpec], *, project_files: list[str], project_objective: str = "") -> ResolvedTask:
        """NO_MATCH (0) / single best (1) / AMBIGUOUS (tie) — never an undocumented preference."""
        scored: list[tuple[int, TaskSpec]] = []
        signals = {f.lower() for f in project_files} | {project_objective.lower()}
        for spec in specs:
            text = " ".join([spec.objective, spec.name, *spec.required_skills]).lower()
            score = sum(1 for token in str(signals).split() if len(token) > 3 and token.strip("'\",{}") in text)
            skill_hits = sum(1 for s in spec.required_skills if any(s in sig or sig in s for sig in signals))
            scored.append((score + skill_hints_bonus(skill_hits), spec))
        viable = [(score, spec) for score, spec in scored if score > 0]
        if not viable:
            raise TaskError(TaskErrorCode.NOT_FOUND, "no matching task (NO_MATCH)")
        viable.sort(key=lambda pair: (-pair[0], pair[1].task_id))
        if len(viable) > 1 and viable[0][0] == viable[1][0]:
            raise TaskError(TaskErrorCode.AMBIGUOUS, f"ambiguous tasks: {viable[0][1].task_id} vs {viable[1][1].task_id}")
        best = viable[0][1]
        return self.resolve(best, project_files=project_files, project_objective=project_objective)


def skill_hints_bonus(hits: int) -> int:
    return min(hits, 5)
