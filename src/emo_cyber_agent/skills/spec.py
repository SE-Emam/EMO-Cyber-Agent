"""Skill specification — POST-RC-001.

A Skill is an executable security-methodology declaration, NOT a prompt.
Skills request capabilities; they never grant them. Skill content is
potentially untrusted: validation reports trust, Core Policy decides.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SKILL_VERSION = "1.0.0"
SKILL_SPEC_VERSION = "1.0"

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Instruction-override patterns: presence marks content untrusted, never trusted.
INJECTION_PATTERNS = (
    "ignore previous instructions",
    "disregard previous",
    "grant permission",
    "disable security",
    "skip verification",
    "system message",
    "developer instruction",
    "security override",
    "mark finding confirmed",
    "trust me",
    "do not verify",
    "ignore system policy",
    "force confirmation",
)

# Capability roots that are never grantable through skills (request-only,
# decided by Core Policy; requesting them marks the skill untrusted).
HIGH_RISK_CAPABILITY_RE = re.compile(r"(admin|write|delete|drop|destroy|mutate|remediat|push|merge|deploy|migrate|sudo|escalat)", re.IGNORECASE)


class SkillTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class SkillSpec(BaseModel):
    """Versioned methodology declaration. Frozen; validated on registration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    skill_id: str = Field(..., min_length=1, max_length=80)
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(..., description="Independent semver X.Y.Z")
    description: str = Field(..., min_length=1, max_length=1000)
    domain: str = Field(..., min_length=1, max_length=60)
    triggers: tuple[str, ...] = Field(default_factory=tuple)
    objectives: tuple[str, ...] = Field(default_factory=tuple)
    inputs: tuple[str, ...] = Field(default_factory=tuple)
    required_capabilities: tuple[str, ...] = Field(default_factory=tuple)
    allowed_tools: tuple[str, ...] = Field(default_factory=tuple)
    methodology: tuple[str, ...] = Field(default_factory=tuple)
    evidence_requirements: tuple[str, ...] = Field(default_factory=tuple)
    verification_strategy: str = ""
    stop_conditions: tuple[str, ...] = Field(default_factory=tuple)
    output_contract: str = ""
    dependencies: tuple[str, ...] = Field(default_factory=tuple)
    security_constraints: tuple[str, ...] = Field(default_factory=tuple)
    provenance: dict[str, Any] = Field(default_factory=dict)
    tests: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("skill_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$", v):
            raise ValueError("skill_id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VERSION_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v


class SkillValidation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    skill_id: str
    version: str
    valid: bool
    trust: SkillTrust = SkillTrust.TRUSTED
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


def scan_injection_phrases(*texts: str) -> list[str]:
    """Return matched injection patterns (case-insensitive). Pure scan, no decisions."""
    hits: list[str] = []
    for text in texts:
        lowered = (text or "").lower()
        for pattern in INJECTION_PATTERNS:
            if pattern in lowered and pattern not in hits:
                hits.append(pattern)
    return hits


def high_risk_capabilities(capabilities: tuple[str, ...]) -> list[str]:
    return [c for c in capabilities if HIGH_RISK_CAPABILITY_RE.search(c)]
