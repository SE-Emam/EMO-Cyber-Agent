"""Playbook domain model — POST-RC-004.

A Playbook is a SECURITY WORKFLOW CONTRACT: an ordered, conditional
composition of Task references + skill/tool/capability requests +
evidence/verification plans + report template ref + stop rules. It
coordinates existing systems (TaskResolver, SkillResolver,
ToolRegistry, ReportTemplateResolver) and authorizes NOTHING.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

PLAYBOOK_SPEC_VERSION = "1.0"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_VER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_TASK_REF_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9](@\d+\.\d+\.\d+)?$")

# Declarative condition subjects. No code, no paths, no expressions.
ALLOWED_CONDITION_FIELDS: tuple[str, ...] = (
    "technology",
    "asset.type",
    "evidence.category",
    "candidate.status",
)
ALLOWED_CONDITION_OPERATORS: tuple[str, ...] = ("==", "!=", "in", "not-in")

# Stop rules every playbook must declare (hard requirements).
REQUIRED_STOP_CONDITIONS: tuple[str, ...] = (
    "policy_violation",
    "scope_violation",
    "task_failure",
)
RECOMMENDED_STOP_CONDITIONS: tuple[str, ...] = (
    "policy_violation",
    "scope_violation",
    "evidence_integrity_failure",
    "security_boundary_break",
    "task_failure",
    "budget_exhausted",
    "no_progress",
    "unresolved_critical_conflict",
)

# Capability requests containing these fragments are write-ish: a
# read-only playbook is incompatible with any task requesting them.
WRITE_CAPABILITY_FRAGMENTS: tuple[str, ...] = ("write", "destructive", "admin", "delete", "exfiltrate")


class PlaybookTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"


class PlaybookStatus(StrEnum):
    PLANNED = "planned"
    RESOLVING = "resolving"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class ResolutionStatus(StrEnum):
    RESOLVED = "resolved"
    PARTIAL = "partial"
    INVALID = "invalid"
    BLOCKED = "blocked"


class PlaybookErrorCode(StrEnum):
    NOT_FOUND = "PLAYBOOK_NOT_FOUND"
    INVALID = "PLAYBOOK_INVALID"
    VERSION_INVALID = "PLAYBOOK_VERSION_INVALID"
    REFERENCE_INVALID = "PLAYBOOK_REFERENCE_INVALID"
    TASK_MISSING = "PLAYBOOK_TASK_MISSING"
    SKILL_MISSING = "PLAYBOOK_SKILL_MISSING"
    TOOL_MISSING = "PLAYBOOK_TOOL_MISSING"
    TEMPLATE_MISSING = "PLAYBOOK_TEMPLATE_MISSING"
    DUPLICATE_TASK = "PLAYBOOK_DUPLICATE_TASK"
    DEPENDENCY_CYCLE = "PLAYBOOK_DEPENDENCY_CYCLE"
    CONDITION_INVALID = "PLAYBOOK_CONDITION_INVALID"
    CAPABILITY_INVALID = "PLAYBOOK_CAPABILITY_INVALID"
    INCOMPATIBLE = "PLAYBOOK_INCOMPATIBLE"
    UNSAFE = "PLAYBOOK_UNSAFE"
    UNTRUSTED = "PLAYBOOK_UNTRUSTED"
    SCOPE_INVALID = "PLAYBOOK_SCOPE_INVALID"
    AMBIGUOUS = "PLAYBOOK_AMBIGUOUS"


class PlaybookError(Exception):
    def __init__(self, code: PlaybookErrorCode, message: str):
        super().__init__(f"{code.value}: {message}")
        self.code = code


class PlaybookCondition(BaseModel):
    """One declarative gate: WHEN <field> <op> <value> SELECT tasks.

    Evaluated against ProjectContext sets only. Empty/unknown context
    selects nothing (fail-closed). select_tasks must be playbook tasks.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    when_field: str = Field(...)
    operator: str = Field(...)
    value: Any = None
    select_tasks: tuple[str, ...] = ()

    @field_validator("when_field")
    @classmethod
    def _field(cls, v: str) -> str:
        if v not in ALLOWED_CONDITION_FIELDS:
            raise ValueError(f"condition field not allowlisted: {v}")
        return v

    @field_validator("operator")
    @classmethod
    def _operator(cls, v: str) -> str:
        if v not in ALLOWED_CONDITION_OPERATORS:
            raise ValueError(f"condition operator not allowlisted: {v}")
        return v

    @field_validator("select_tasks")
    @classmethod
    def _refs(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for ref in v:
            if not _TASK_REF_RE.match(ref):
                raise ValueError(f"task ref not kebab-case[@semver]: {ref}")
        return v


class ProjectContext(BaseModel):
    """Plain resolution input: what the project IS, not what to do."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    technologies: tuple[str, ...] = ()
    asset_types: tuple[str, ...] = ()
    evidence_categories: tuple[str, ...] = ()
    candidate_statuses: tuple[str, ...] = ()


class PlaybookSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    playbook_id: str = Field(...)
    title: str = Field(..., min_length=1, max_length=120)
    version: str = Field(...)
    type: str = Field(default="security")
    objective: str = Field(..., min_length=1, max_length=2000)
    description: str = Field(default="", max_length=2000)
    required_tasks: tuple[str, ...] = ()
    optional_tasks: tuple[str, ...] = ()
    required_skills: tuple[str, ...] = ()
    optional_skills: tuple[str, ...] = ()
    required_tools: tuple[str, ...] = ()
    optional_tools: tuple[str, ...] = ()
    requested_capabilities: tuple[str, ...] = ()
    denied_capabilities: tuple[str, ...] = ()
    execution_order: tuple[str, ...] = ()
    conditions: tuple[PlaybookCondition, ...] = ()
    max_tasks: int = Field(default=12, ge=1, le=64)
    max_iterations: int = Field(default=1, ge=1, le=8)
    evidence_required: tuple[str, ...] = ()
    evidence_provenance_required: bool = True
    verification_required: bool = True
    verification_methods: tuple[str, ...] = ()
    report_template: str = ""
    stop_conditions: tuple[str, ...] = ()
    acceptance_criteria: tuple[str, ...] = ()
    security_read_only_default: bool = True
    security_forbidden_actions: tuple[str, ...] = ()
    security_external_targets: str = "deny"
    security_secrets_policy: str = "strict"
    security_untrusted_content: bool = True
    extends: str | None = None
    dependencies: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("playbook_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("playbook_id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VER_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @field_validator("required_tasks", "optional_tasks")
    @classmethod
    def _task_refs(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for ref in v:
            if not _TASK_REF_RE.match(ref):
                raise ValueError(f"task ref not kebab-case[@semver]: {ref}")
        return v

    @field_validator("extends")
    @classmethod
    def _extends(cls, v: str | None) -> str | None:
        if v is not None and not _ID_RE.match(v):
            raise ValueError("extends must be kebab-case playbook id")
        return v

    @field_validator("dependencies")
    @classmethod
    def _deps(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for dep in v:
            if not _ID_RE.match(dep):
                raise ValueError(f"dependency not kebab-case: {dep}")
        return v


def task_ref_id(ref: str) -> str:
    return ref.split("@", 1)[0]


def task_ref_version(ref: str) -> str | None:
    return ref.split("@", 1)[1] if "@" in ref else None


def is_write_capability(cap: str) -> bool:
    lowered = cap.lower()
    return any(frag in lowered for frag in WRITE_CAPABILITY_FRAGMENTS)


class ResolvedPlaybookTask(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    task_id: str
    task_version: str
    pinned_ref: str
    status: str = ""
    selected_by: str = "required"
    skill_versions: dict[str, str] = Field(default_factory=dict)
    tool_versions: dict[str, str] = Field(default_factory=dict)


class PlaybookPlan(BaseModel):
    """Execution graph (SEQUENTIAL + conditional selection). No execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    playbook_id: str
    playbook_version: str
    ordered_task_ids: tuple[str, ...] = ()
    skipped_tasks: tuple[str, ...] = ()
    conditions_evaluated: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    expected_evidence: tuple[str, ...] = ()
    stop_rules: tuple[str, ...] = ()
    report_template: str = ""


class ResolvedPlaybook(BaseModel):
    """Immutable resolution snapshot: identity + everything downstream needs."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    playbook_id: str
    playbook_version: str
    status: ResolutionStatus = ResolutionStatus.RESOLVED
    tasks: tuple[ResolvedPlaybookTask, ...] = ()
    skipped_optional_tasks: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()
    skill_versions: dict[str, str] = Field(default_factory=dict)
    requested_tools: tuple[str, ...] = ()
    tool_versions: dict[str, str] = Field(default_factory=dict)
    requested_capabilities: tuple[str, ...] = ()
    denied_capabilities: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    verification_requirements: tuple[str, ...] = ()
    verification_methods: tuple[str, ...] = ()
    report_template: str = ""
    report_template_version: str = ""
    report_template_known: bool = False
    plan: PlaybookPlan | None = None
    lifecycle: PlaybookStatus = PlaybookStatus.READY
    policy_version: str = ""
    resolved_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    digest: str = ""
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @staticmethod
    def digest_of(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()
