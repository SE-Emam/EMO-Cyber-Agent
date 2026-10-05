"""Task domain model — POST-RC-002.

A Task is a Security Execution Contract: WHAT should be done, with which
skills/tools/capabilities (requested, never granted), what evidence and
verification it requires, and when it stops. It never permits, executes,
confirms, or reports anything by itself — Core does.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

TASK_SPEC_VERSION = "1.0"

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")


class TaskType(StrEnum):
    AUDIT = "audit"
    REVIEW = "review"
    VERIFICATION_SUPPORT = "verification_support"
    THREAT_MODEL = "threat_model"


class TaskTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"


class ResolutionStatus(StrEnum):
    RESOLVED = "resolved"
    PARTIAL = "partial"
    INVALID = "invalid"
    BLOCKED = "blocked"


class TaskErrorCode(StrEnum):
    NOT_FOUND = "TASK_NOT_FOUND"
    INVALID = "TASK_INVALID"
    VERSION_INVALID = "TASK_VERSION_INVALID"
    SCOPE_INVALID = "TASK_SCOPE_INVALID"
    CAPABILITY_INVALID = "TASK_CAPABILITY_INVALID"
    SKILL_MISSING = "TASK_SKILL_MISSING"
    TOOL_MISSING = "TASK_TOOL_MISSING"
    TEMPLATE_MISSING = "TASK_TEMPLATE_MISSING"
    DEPENDENCY_CYCLE = "TASK_DEPENDENCY_CYCLE"
    AMBIGUOUS = "TASK_AMBIGUOUS"
    UNSAFE = "TASK_UNSAFE"
    UNTRUSTED = "TASK_UNTRUSTED"


class TaskError(Exception):
    def __init__(self, code: TaskErrorCode, message: str):
        super().__init__(f"{code.value}: {message}")
        self.code = code


class TaskScope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    included: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()
    target_types: tuple[str, ...] = ()

    def narrowed_by(self, outer: TaskScope) -> bool:
        """True if self fits inside outer (narrowing only, never widening)."""
        if outer.target_types and any(t not in outer.target_types for t in self.target_types):
            return False
        if outer.included and any(i not in outer.included for i in self.included):
            return False
        return True


class TaskSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(...)
    type: TaskType = Field(default=TaskType.AUDIT)
    objective: str = Field(..., min_length=1, max_length=2000)
    scope: TaskScope = Field(default_factory=TaskScope)
    inputs_required: tuple[str, ...] = ()
    inputs_optional: tuple[str, ...] = ()
    required_skills: tuple[str, ...] = ()
    optional_skills: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    denied_capabilities: tuple[str, ...] = ()
    required_tools: tuple[str, ...] = ()
    optional_tools: tuple[str, ...] = ()
    methodology_phases: tuple[str, ...] = ()
    methodology_procedures: tuple[str, ...] = ()
    evidence_required: tuple[str, ...] = ()
    evidence_provenance_required: bool = True
    evidence_minimum_quality: str = "sourced-with-locator"
    verification_required: bool = True
    verification_methods: tuple[str, ...] = ()
    verification_confirmation: str = ""
    verification_refutation: str = ""
    verification_stop_conditions: tuple[str, ...] = ()
    security_read_only_default: bool = True
    security_forbidden_actions: tuple[str, ...] = ()
    security_external_targets: str = "deny"
    security_secrets_policy: str = "redact-and-never-persist"
    security_untrusted_content: str = "data-only"
    stop_conditions: tuple[str, ...] = ()
    acceptance_criteria: tuple[str, ...] = ()
    deliverables: tuple[str, ...] = ()
    report_template: str = ""
    report_required_sections: tuple[str, ...] = ()
    extends: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("task_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("task_id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VERSION_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @field_validator("extends")
    @classmethod
    def _extends(cls, v: str | None) -> str | None:
        if v is not None and not _ID_RE.match(v):
            raise ValueError("extends must be kebab-case task id")
        return v


class ResolvedSkill(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    skill_id: str
    version: str
    reason: str = ""


class ResolvedTask(BaseModel):
    """Immutable resolution snapshot: registry state frozen at resolve time."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    task_id: str
    task_version: str
    status: ResolutionStatus = ResolutionStatus.RESOLVED
    skills: tuple[ResolvedSkill, ...] = ()
    skipped_optional_skills: tuple[str, ...] = ()
    requested_tools: tuple[str, ...] = ()
    requested_capabilities: tuple[str, ...] = ()
    denied_capabilities: tuple[str, ...] = ()
    scope: TaskScope = Field(default_factory=TaskScope)
    methodology_phases: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    verification_requirements: tuple[str, ...] = ()
    verification_methods: tuple[str, ...] = ()
    report_template: str = ""
    report_template_known: bool = False
    stop_conditions: tuple[str, ...] = ()
    acceptance_criteria: tuple[str, ...] = ()
    skill_versions: dict[str, str] = Field(default_factory=dict)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    report_template_version: str = ""
    policy_version: str = ""
    resolved_at: str = ""
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
