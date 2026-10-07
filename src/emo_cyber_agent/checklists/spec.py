"""Frozen checklist spec — POST-T020.

A :class:`Checklist` is review guidance as pure DATA: ``id`` (kebab),
``version`` (semver), ``scope`` (applicability boundary), and an
ordered ``items`` tuple. A :class:`ChecklistItem` names one review
point: ``id``, ``check``, ``expected_evidence``,
``verification_requirement``, and ``acceptance_condition``.

Checklists GRANT NOTHING: there are no capability, policy, or severity
fields, no verdicts, no scoring, and no execution. Evidence is
reviewer-supplied; probing happens elsewhere.

Shape reuses ``subagent.bootstrap`` conventions (frozen pydantic,
``extra="forbid"``, ``to_dict`` / ``from_dict`` /
``to_canonical_json``, deterministic order) for the distinct security
review domain.
"""

from __future__ import annotations

import json
import re
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = ["Checklist", "ChecklistItem"]

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_VER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def _non_blank(label: str, value: str, max_len: int = 2000) -> str:
    if not value.strip():
        raise ValueError(f"{label} must be non-empty")
    if len(value) > max_len:
        raise ValueError(f"{label} must be at most {max_len} chars")
    return value


class ChecklistItem(BaseModel):
    """One frozen review point. Data only — never executed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(...)
    check: str = Field(min_length=1, max_length=2000)
    expected_evidence: str = Field(min_length=1, max_length=2000)
    verification_requirement: str = Field(min_length=1, max_length=2000)
    acceptance_condition: str = Field(min_length=1, max_length=2000)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("item id must be kebab-case")
        return v

    @field_validator("check", "expected_evidence", "verification_requirement", "acceptance_condition")
    @classmethod
    def _text(cls, v: str) -> str:
        return _non_blank("field", v)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class Checklist(BaseModel):
    """One frozen, versioned, scope-bound review checklist. Data only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(...)
    version: str = Field(...)
    scope: str = Field(min_length=1, max_length=120)
    items: tuple[ChecklistItem, ...] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("checklist id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not _VER_RE.match(v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @field_validator("scope")
    @classmethod
    def _scope(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("scope must be kebab-case")
        return v

    @field_validator("items")
    @classmethod
    def _items(cls, v: tuple[ChecklistItem, ...]) -> tuple[ChecklistItem, ...]:
        seen = set()
        for item in v:
            if item.id in seen:
                raise ValueError(f"duplicate item id: {item.id}")
            seen.add(item.id)
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
