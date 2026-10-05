"""Playbook validator — POST-RC-004 (declarative checks only).

Structural validation + reference existence (when registries wired) +
read-only compatibility + result-bias + injection quarantine. Advisory:
grants nothing, executes nothing.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict

from emo_cyber_agent.playbooks.spec import (
    RECOMMENDED_STOP_CONDITIONS,
    REQUIRED_STOP_CONDITIONS,
    PlaybookSpec,
    PlaybookTrust,
    is_write_capability,
    task_ref_id,
)

_UNSAFE_RE = re.compile(r"(ignore\s+(all\s+)?(previous|prior)\s+instructions|grant\s+\w+\s+access|mark\s+\w+\s+confirmed|disable\s+verification|run\s+(a\s+)?command|export\s+secrets|os\.system|subprocess|__import__|eval\(|exec\()", re.IGNORECASE)
_RESULT_BIAS_RE = re.compile(r"(at least one|must be found|must find|guarantee|ensure .*(high|critical).*(found|confirmed))", re.IGNORECASE)
_CODE_RE = re.compile(r"(\bimport\s+os\b|\bsubprocess\b|\bos\.system\b|__import__|eval\(|exec\(|;\s*rm\s+|-rf\s+/)", re.IGNORECASE)


class PlaybookValidation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    valid: bool = False
    trust: PlaybookTrust = PlaybookTrust.INVALID
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class PlaybookValidator:
    """Schema + refs + compatibility + safety. Declarative only."""

    UNSAFE_MARKERS = ("javascript:", "<script", "exec(", "eval(", "__import__", "os.system", "subprocess", "fetch(", "XMLHttpRequest", "import os", "require(")

    def __init__(self, *, task_registry: Any = None, skill_registry: Any = None, tool_registry: Any = None, template_registry: Any = None):
        self._tasks = task_registry
        self._skills = skill_registry
        self._tools = tool_registry
        self._templates = template_registry

    def validate(self, spec: PlaybookSpec) -> PlaybookValidation:
        errors: list[str] = []
        warnings: list[str] = []
        # --- shape ---
        if not spec.objective.strip():
            errors.append("missing-objective")
        if not spec.acceptance_criteria:
            errors.append("missing-acceptance-criteria")
        if not spec.stop_conditions:
            errors.append("missing-stop-conditions")
        if not spec.required_tasks and not spec.optional_tasks:
            errors.append("missing-tasks")
        # --- duplicate tasks ---
        seen: set[str] = set()
        for ref in (*spec.required_tasks, *spec.optional_tasks):
            tid = task_ref_id(ref)
            if tid in seen:
                errors.append(f"duplicate-task:{tid}")
            seen.add(tid)
        overlap = {task_ref_id(r) for r in spec.required_tasks} & {task_ref_id(r) for r in spec.optional_tasks}
        if overlap:
            errors.append(f"duplicate-task:{sorted(overlap)[0]}")
        # --- execution order must reference declared tasks ---
        declared = {task_ref_id(r) for r in (*spec.required_tasks, *spec.optional_tasks)}
        for tid in spec.execution_order:
            if tid not in declared:
                errors.append(f"order-unknown-task:{tid}")
        # --- required stop conditions ---
        for stop in REQUIRED_STOP_CONDITIONS:
            if stop not in spec.stop_conditions:
                errors.append(f"stop-missing:{stop}")
        for stop in RECOMMENDED_STOP_CONDITIONS:
            if stop not in spec.stop_conditions:
                warnings.append(f"stop-recommended:{stop}")
        # --- capabilities: requested ∩ denied must be empty ---
        clash = set(spec.requested_capabilities) & set(spec.denied_capabilities)
        if clash:
            errors.append(f"capability-clash:{sorted(clash)[0]}")
        for cap in spec.requested_capabilities:
            if is_write_capability(cap) and spec.security_read_only_default:
                warnings.append(f"capability-write-requested:{cap}")
        # --- fail-closed evidence / verification / external gates ---
        if not spec.evidence_provenance_required:
            errors.append("evidence-provenance-required")
        if not spec.verification_required:
            errors.append("verification-required")
        if spec.security_external_targets != "deny":
            errors.append("external-targets-denied")
        if not spec.security_read_only_default:
            warnings.append("read-only-disabled")
        # --- result bias in acceptance ---
        for criterion in spec.acceptance_criteria:
            if _RESULT_BIAS_RE.search(criterion):
                errors.append("result-bias:acceptance-predetermines-outcome")
        # --- unsafe text / injection (quarantine, still usable as data) ---
        quarantined = False
        haystacks = [spec.objective, spec.description, *spec.acceptance_criteria, *[c.value if isinstance(c.value, str) else "" for c in spec.conditions]]
        for hay in haystacks:
            lowered = (hay or "").lower()
            if _UNSAFE_RE.search(hay or "") or _CODE_RE.search(hay or "") or any(m in lowered for m in self.UNSAFE_MARKERS):
                quarantined = True
                break
        # --- conditions: select_tasks must be declared; warn on empty select ---
        for cond in spec.conditions:
            for ref in cond.select_tasks:
                if task_ref_id(ref) not in declared:
                    errors.append(f"condition-unknown-task:{ref}")
            if not cond.select_tasks:
                warnings.append(f"condition-empty-select:{cond.when_field}")
        # --- references (when registries wired; else pending warning) ---
        errors, warnings = self._check_refs(spec, errors, warnings)
        # --- trust ---
        trust = PlaybookTrust.UNTRUSTED
        if quarantined:
            warnings.append("injection-quarantined")
        if not errors and not quarantined and spec.provenance.get("source") == "official":
            trust = PlaybookTrust.TRUSTED
        return PlaybookValidation(valid=not errors, trust=trust if not errors else PlaybookTrust.INVALID, errors=tuple(errors), warnings=tuple(warnings))

    def _check_refs(self, spec: PlaybookSpec, errors: list[str], warnings: list[str]) -> tuple[list[str], list[str]]:
        # tasks (+ read-only compatibility against real task caps).
        # Required refs must exist; optional refs missing → warning + skip.
        for ref in spec.required_tasks:
            tid, ver = task_ref_id(ref), None
            if "@" in ref:
                _, ver = ref.split("@", 1)
            if self._tasks is None:
                warnings.append(f"task-unverified:{tid}")
                continue
            try:
                task = self._tasks.get(tid, ver)
            except Exception:
                errors.append(f"task-missing:{ref}")
                continue
            if spec.security_read_only_default:
                for cap in (*getattr(task, "required_capabilities", ()), *getattr(task, "optional_tools", ())):
                    if is_write_capability(str(cap)):
                        errors.append(f"incompatible:read-only-playbook+write-task:{tid}:{cap}")
                        break
        for ref in spec.optional_tasks:
            tid = task_ref_id(ref)
            if self._tasks is None:
                warnings.append(f"task-unverified:{tid}")
            else:
                try:
                    self._tasks.get(tid, ref.split("@", 1)[1] if "@" in ref else None)
                except Exception:
                    warnings.append(f"optional-task-missing:{ref}")
        # skills
        for skill in spec.required_skills:
            if self._skills is None:
                warnings.append(f"skill-unverified:{skill}")
                continue
            try:
                self._skills.get(skill)
            except Exception:
                errors.append(f"skill-missing:{skill}")
        for skill in spec.optional_skills:
            if self._skills is None:
                warnings.append(f"skill-unverified:{skill}")
            else:
                try:
                    self._skills.get(skill)
                except Exception:
                    warnings.append(f"optional-skill-missing:{skill}")
        # tools
        for tool in spec.required_tools:
            if self._tools is None:
                warnings.append(f"tool-unverified:{tool}")
                continue
            try:
                self._tools.get(tool)
            except Exception:
                errors.append(f"tool-missing:{tool}")
        for tool in spec.optional_tools:
            if self._tools is None:
                warnings.append(f"tool-unverified:{tool}")
            else:
                try:
                    self._tools.get(tool)
                except Exception:
                    warnings.append(f"optional-tool-absent:{tool}")
        # report template
        if spec.report_template:
            if self._templates is None:
                warnings.append(f"template-unverified:{spec.report_template}")
            else:
                try:
                    self._templates.get(spec.report_template)
                except Exception:
                    errors.append(f"template-missing:{spec.report_template}")
        # extends / dependencies existence (registry-level, when self registry known)
        return errors, warnings
