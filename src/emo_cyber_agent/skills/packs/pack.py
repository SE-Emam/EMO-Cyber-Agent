"""Security skill pack domain — POST-RC-006.

A pack is reusable security METHODOLOGY: checks with evidence
contracts and verification handoffs. It grants nothing, executes
nothing, confirms nothing. Outputs are methodology, hypotheses
(labeled UNVERIFIED), evidence requirements, and verification
requirements — consumed downstream by Correlation and Verification.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

PACK_SPEC_VERSION = "1.0"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_VER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Fragments that make a requested capability write-ish. Packs are
# methodology: they may only request read-only capabilities.
WRITE_CAPABILITY_FRAGMENTS: tuple[str, ...] = ("write", "destructive", "admin", "delete", "exfiltrate", "grant")

# Vocabulary a check may assert WITHOUT verification. Anything stronger
# (CONFIRMED, severity ratings, verdicts) is VERDICT_AUTHORITY.
EVIDENCE_LEVELS: tuple[str, ...] = ("OBSERVED", "SUSPECTED", "HYPOTHESIS", "VERIFICATION_REQUIRED", "VERIFIED")

# Verdict/authority markers banned from all pack text (methodology,
# hypotheses, criteria). Matched case-insensitively.
VERDICT_MARKERS: tuple[str, ...] = (
    "confirmed vulnerability", "confirmed finding", "severity: high", "severity: critical",
    "severity high", "severity critical", "cvss", "exploit succeeded", "exploitation confirmed",
    "vulnerability confirmed", "mark confirmed", "definitely vulnerable", "proven vulnerable",
)


class PackTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"


class CheckCoverage(StrEnum):
    COVERED = "covered"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


def is_write_capability(cap: str) -> bool:
    lowered = cap.lower()
    return any(frag in lowered for frag in WRITE_CAPABILITY_FRAGMENTS)


def contains_verdict(text: str) -> str | None:
    lowered = (text or "").lower()
    for marker in VERDICT_MARKERS:
        if marker in lowered:
            return marker
    return None


class SecurityCheck(BaseModel):
    """One methodology unit: HOW to investigate, WHAT evidence it needs,
    WHAT verification it hands off. Never a verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    check_id: str = Field(...)
    title: str = Field(..., min_length=1, max_length=160)
    methodology: tuple[str, ...] = ()
    evidence_required: tuple[str, ...] = ()
    evidence_sufficient: tuple[str, ...] = ()
    evidence_missing: tuple[str, ...] = ()
    verification_required: tuple[str, ...] = ()
    verification_safety: str = Field(default="passive", max_length=40)
    high_risk: bool = False
    entry_level: str = Field(default="HYPOTHESIS", max_length=24)
    codeintel_needs: tuple[str, ...] = ()
    source_kinds: tuple[str, ...] = ()
    sink_kinds: tuple[str, ...] = ()
    hypothesis_template: str = Field(default="", max_length=1000)

    @field_validator("check_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("check_id must be kebab-case")
        return v

    @field_validator("entry_level")
    @classmethod
    def _level(cls, v: str) -> str:
        if v not in EVIDENCE_LEVELS or v == "VERIFIED":
            raise ValueError("entry_level must be OBSERVED, SUSPECTED, HYPOTHESIS, or VERIFICATION_REQUIRED (never VERIFIED)")
        return v


class SecuritySkillPack(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pack_id: str = Field(...)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(...)
    purpose: str = Field(..., min_length=1, max_length=1000)
    skills: tuple[str, ...] = ()
    required_code_intelligence: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    required_verification: tuple[str, ...] = ()
    applicable_assets: tuple[str, ...] = ()
    security_domains: tuple[str, ...] = ()
    methodology: tuple[str, ...] = ()
    checks: tuple[SecurityCheck, ...] = ()
    stop_conditions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    denied_capabilities: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("pack_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("pack_id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VER_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @field_validator("dependencies")
    @classmethod
    def _deps(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for dep in v:
            if not _ID_RE.match(dep):
                raise ValueError(f"dependency not kebab-case: {dep}")
        return v

    @staticmethod
    def digest_of(pack: SecuritySkillPack) -> str:
        canonical = json.dumps(pack.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


class ResolvedCheck(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    check_id: str
    title: str
    coverage: CheckCoverage = CheckCoverage.COVERED
    missing_capabilities: tuple[str, ...] = ()
    evidence_required: tuple[str, ...] = ()
    verification_required: tuple[str, ...] = ()
    hypothesis: str = ""


class ResolvedPack(BaseModel):
    """Immutable resolution: pack + provider capabilities → coverage plan."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    pack_id: str
    pack_version: str
    pack_digest: str = ""
    status: str = "resolved"
    checks: tuple[ResolvedCheck, ...] = ()
    evidence_plan: tuple[str, ...] = ()
    verification_plan: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    coverage_gaps: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    report_template: str = ""
    resolved_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class PackReportView(BaseModel):
    """Projection-only metadata for report templates. No findings, no verdicts."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    pack_id: str
    pack_version: str
    pack_digest: str = ""
    security_domain: str = ""
    checks_performed: tuple[str, ...] = ()
    evidence_coverage: tuple[str, ...] = ()
    codeintel_coverage: tuple[str, ...] = ()
    verification_status: str = "REQUIRED"
    limitations: tuple[str, ...] = ()
    unverified_hypotheses: tuple[str, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)


class PackResolution(BaseModel):
    """Task → skills → packs → codeintel → evidence/verification handoff."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    task_id: str = ""
    skills: tuple[str, ...] = ()
    packs: tuple[ResolvedPack, ...] = ()
    required_codeintel: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    verification_requirements: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    digest: str = ""
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @staticmethod
    def digest_of(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()
