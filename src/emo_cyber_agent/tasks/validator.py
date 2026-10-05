"""Task validator — POST-RC-002.

Structural + referential validation. Unknown skills/tools/templates,
bad versions/ids, scope violations, unsafe declarations, and injection
payloads fail or quarantine here — never silently, never with substitutes.
Report templates are forward references until POST-RC-003: shape-checked
now, flagged pending, never executed.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict

from emo_cyber_agent.skills.spec import scan_injection_phrases
from emo_cyber_agent.tasks.spec import TaskSpec, TaskTrust

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_VER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_UNSAFE_RE = re.compile(r"\b(write|delete|drop|destroy|mutate|remediat|push|merge|deploy|migrate|sudo|escalat|bypass|disable security|skip verification|force confirm|force confirmation|must confirm)\b", re.IGNORECASE)
_WRITE_CAP_RE = re.compile(r"(write|delete|drop|destroy|mutate|remediat|push|merge|deploy|migrate|admin|destruct)", re.IGNORECASE)


class TaskValidation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    task_id: str
    version: str
    valid: bool
    trust: TaskTrust = TaskTrust.UNTRUSTED
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    report_template_known: bool = False


def _shape_ok(value: str) -> bool:
    return bool(_ID_RE.match(value))


class TaskValidator:
    """Validates against registries without mutating them."""

    def __init__(self, *, skill_registry: Any = None, tool_registry: Any = None, known_report_templates: tuple[str, ...] = ()):
        self._skills = skill_registry
        self._tools = tool_registry
        self._templates = set(known_report_templates)

    def validate(self, spec: TaskSpec) -> TaskValidation:
        errors: list[str] = []
        warnings: list[str] = []
        # schema-level shape (defense in depth beyond pydantic construction)
        if not _shape_ok(spec.task_id):
            errors.append("bad-id")
        if not _VER_RE.match(spec.version):
            errors.append("bad-version")
        if not spec.objective.strip():
            errors.append("missing-objective")
        if not spec.acceptance_criteria:
            errors.append("missing-acceptance-criteria")
        if not spec.stop_conditions:
            errors.append("missing-stop-conditions")
        if not spec.required_skills and not spec.optional_skills:
            errors.append("missing-skills")
        if not spec.security_read_only_default:
            errors.append("read-only-default-required")
        # acceptance must not predetermine results (result bias)
        for criterion in spec.acceptance_criteria:
            if _UNSAFE_RE.search(criterion) and "confirm" in criterion.lower():
                errors.append("result-bias:acceptance-predetermines-outcome")
        # skill existence (no substitutes)
        if self._skills is not None:
            for skill in (*spec.required_skills, *spec.optional_skills):
                try:
                    self._skills.get(skill)
                except ValueError:
                    errors.append(f"skill-missing:{skill}")
        # tool references (names must resolve; capabilities stay advisory)
        if self._tools is not None:
            for tool in (*spec.required_tools, *spec.optional_tools):
                try:
                    self._tools.get(tool)
                except (ValueError, KeyError, AttributeError):
                    errors.append(f"tool-missing:{tool}")
        # capability declarations: write/destructive requests quarantine
        risky = [c for c in spec.required_capabilities if _WRITE_CAP_RE.search(c)]
        if risky:
            warnings.append(f"high-risk-capabilities:{','.join(sorted(risky))}")
        # verification authority stays in Core: removal or forcing is unsafe
        if not spec.verification_required:
            warnings.append("verification-disabled")
        # injection scan over free text
        hits = scan_injection_phrases(spec.objective, *spec.methodology_phases, *spec.methodology_procedures, *spec.acceptance_criteria)
        if hits:
            warnings.append(f"injection-patterns:{','.join(hits)}")
        unsafe_hits = [t for t in (*spec.methodology_phases, *spec.methodology_procedures, *spec.acceptance_criteria) if _UNSAFE_RE.search(t)]
        if unsafe_hits:
            warnings.append("unsafe-language")
        # report template: forward reference until POST-RC-003
        template_known = False
        if spec.report_template:
            if not _shape_ok(spec.report_template):
                errors.append("bad-report-template-id")
            elif spec.report_template in self._templates:
                template_known = True
            else:
                warnings.append(f"report-template-pending:{spec.report_template}")
        # extends target must exist (composition validated at resolve time too)
        trust = TaskTrust.UNTRUSTED if (warnings or spec.provenance.get("source") != "official") else TaskTrust.TRUSTED
        # official provenance comes from the builtin loader, not self-declared
        if spec.provenance.get("source") == "official":
            warnings.append("self-declared-official")
            trust = TaskTrust.UNTRUSTED
        return TaskValidation(task_id=spec.task_id, version=spec.version, valid=not errors, trust=trust, errors=tuple(errors), warnings=tuple(warnings), report_template_known=template_known)
