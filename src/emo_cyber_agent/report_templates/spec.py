"""Report template domain — POST-RC-003.

A template is a PRESENTATION contract: what to show, how to organize,
which sections are visible, how evidence renders. It can never change a
finding, severity, confidence, verification, evidence, policy, or state.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

TEMPLATE_SPEC_VERSION = "1.0"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_VER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Allowlisted finding field paths a template may project. Nothing else is addressable.
ALLOWED_FINDING_FIELDS: tuple[str, ...] = (
    "finding.title", "finding.description", "finding.category", "finding.severity",
    "finding.confidence", "finding.status", "finding.cwe", "finding.owasp",
    "finding.locations", "finding.evidence_ids", "finding.verification_ids",
    "finding.remediation", "finding.provenance", "finding.asset_id",
    "finding.candidate_id", "finding.finding_id", "finding.observed_issue",
    "finding.root_cause", "finding.impact", "finding.references",
)

# Mandatory security fields: no template may drop them when the finding carries them.
MANDATORY_FINDING_FIELDS: tuple[str, ...] = (
    "finding.finding_id", "finding.status", "finding.severity",
    "finding.confidence", "finding.evidence_ids", "finding.verification_ids",
    "finding.provenance",
)

# Visibility rule operator allowlist. No expressions, no calls, no access.
ALLOWED_OPERATORS: tuple[str, ...] = ("==", "!=", "in", "not-in")
ALLOWED_CONDITION_PATHS: tuple[str, ...] = (
    "finding.cwe", "finding.owasp", "finding.severity", "finding.status",
    "finding.category", "verification.status",
)


class TemplateTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"


class TemplateErrorCode(StrEnum):
    NOT_FOUND = "REPORT_TEMPLATE_NOT_FOUND"
    INVALID = "REPORT_TEMPLATE_INVALID"
    UNSAFE = "REPORT_TEMPLATE_UNSAFE"
    VERSION_INVALID = "REPORT_TEMPLATE_VERSION_INVALID"
    FIELD_INVALID = "REPORT_TEMPLATE_FIELD_INVALID"
    RULE_INVALID = "REPORT_TEMPLATE_RULE_INVALID"
    FORMAT_UNSUPPORTED = "REPORT_TEMPLATE_FORMAT_UNSUPPORTED"
    COMPOSITION_INVALID = "REPORT_TEMPLATE_COMPOSITION_INVALID"


class TemplateError(Exception):
    def __init__(self, code: TemplateErrorCode, message: str):
        super().__init__(f"{code.value}: {message}")
        self.code = code


class VisibilityRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    show_if_field: str = Field(..., min_length=1)
    operator: str = Field(...)
    value: Any = None

    @field_validator("operator")
    @classmethod
    def _operator(cls, v: str) -> str:
        if v not in ALLOWED_OPERATORS:
            raise ValueError(f"operator not allowlisted: {v}")
        return v

    @field_validator("show_if_field")
    @classmethod
    def _path(cls, v: str) -> str:
        if v not in ALLOWED_CONDITION_PATHS:
            raise ValueError(f"condition path not allowlisted: {v}")
        return v

    def applies(self, finding_view: dict[str, Any], verification_status: str = "") -> bool:
        actual: Any = None
        if self.show_if_field == "verification.status":
            actual = verification_status
        elif self.show_if_field.startswith("finding."):
            actual = finding_view.get(self.show_if_field[len("finding."):])
        if self.operator == "==":
            return actual == self.value
        if self.operator == "!=":
            return actual != self.value
        if self.operator == "in":
            return actual in (self.value if isinstance(self.value, list) else [self.value])
        if self.operator == "not-in":
            return actual not in (self.value if isinstance(self.value, list) else [self.value])
        return False


class TemplateSection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str = Field(..., min_length=1, max_length=60)
    fields: tuple[str, ...] = ()
    visibility: tuple[VisibilityRule, ...] = ()

    @field_validator("fields")
    @classmethod
    def _fields(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for field in v:
            if field not in ALLOWED_FINDING_FIELDS and not field.startswith("report.") and not field.startswith("meta."):
                raise ValueError(f"field not allowlisted: {field}")
        return v


class ReportTemplateSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    template_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(...)
    type: str = Field(default="security")
    description: str = Field(default="", max_length=1000)
    sections: tuple[TemplateSection, ...] = ()
    finding_fields: tuple[str, ...] = ()
    section_order: tuple[str, ...] = ()
    show_non_reportable: bool = False
    evidence_presentation: str = "references"
    verification_presentation: str = "status"
    limitations_sections: tuple[str, ...] = ("limitations",)
    appendices: tuple[str, ...] = ()
    output_formats: tuple[str, ...] = ("json", "jsonl", "markdown")
    extends: str | None = None
    preserve_provenance: bool = True
    redact_secrets: bool = True
    deterministic: bool = True
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("template_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("template_id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VER_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @field_validator("finding_fields")
    @classmethod
    def _finding_fields(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for field in v:
            if field not in ALLOWED_FINDING_FIELDS and not field.startswith("report.") and not field.startswith("meta."):
                raise ValueError(f"field not allowlisted: {field}")
        return v

    @field_validator("output_formats")
    @classmethod
    def _formats(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for fmt in v:
            if fmt not in ("json", "jsonl", "markdown"):
                raise ValueError(f"unsupported output format: {fmt}")
        if not v:
            raise ValueError("at least one output format required")
        return v

    @field_validator("extends")
    @classmethod
    def _extends(cls, v: str | None) -> str | None:
        if v is not None and not _ID_RE.match(v):
            raise ValueError("extends must be kebab-case template id")
        return v


class ResolvedReportTemplate(BaseModel):
    """Immutable snapshot: id + version + digest + resolution time."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    template_id: str
    version: str
    digest: str = ""
    resolved_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    spec: ReportTemplateSpec | None = None

    @staticmethod
    def digest_of(spec: ReportTemplateSpec) -> str:
        canonical = json.dumps(spec.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


class ReportTemplatePack(BaseModel):
    """Future distribution manifest (declared now, distribution deferred)."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    pack_id: str = Field(..., min_length=1)
    version: str = Field(...)
    templates: tuple[str, ...] = ()
    supported_formats: tuple[str, ...] = ("json", "jsonl", "markdown")
    provenance: dict[str, Any] = Field(default_factory=dict)
    trust: TemplateTrust = TemplateTrust.UNTRUSTED

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VER_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v
