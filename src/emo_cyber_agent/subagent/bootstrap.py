"""Host bootstrap readiness checklist — POST-T018.

Host-side readiness as pure DATA. This module never probes the system:
no I/O, no clock, no subprocess, no shell, no imports of probing
machinery. Evidence is caller-supplied facts (``evidence_dict``); probing
is the host/doctor's job (see ``cli/main.py doctor`` as reference).

:class:`BootstrapCheck` is one checklist item (``name``, ``required``,
``check_kind``). :func:`bootstrap_profile` returns the ordered checklist
for a host. :func:`evaluate` folds caller-supplied evidence into a closed
verdict:

- any missing ``required`` check → ``BLOCKED``
- otherwise any missing optional check → ``DEGRADED`` (warnings)
- otherwise → ``READY``

Deterministic: input order of ``checks`` is preserved in outputs;
repeated calls with equal inputs give equal results.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "PYTHON_VERSION_WINDOW",
    "BootstrapCheck",
    "BootstrapCheckKind",
    "BootstrapEvaluation",
    "BootstrapStatus",
    "bootstrap_profile",
    "evaluate",
]

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")

#: Documented host python window (mirrors ``pyproject.toml`` requires-python).
PYTHON_VERSION_WINDOW = ">=3.11"


class BootstrapCheckKind(StrEnum):
    """How the host should probe a check. Mechanism only, never executed here."""

    VERSION_WINDOW = "version-window"
    PRESENCE = "presence"


class BootstrapStatus(StrEnum):
    READY = "ready"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


class BootstrapCheck(BaseModel):
    """Frozen checklist item. Data only — never executed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    required: bool = Field(...)
    check_kind: BootstrapCheckKind = Field(...)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("check name must be non-empty")
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class BootstrapEvaluation(BaseModel):
    """Frozen verdict of :func:`evaluate`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: BootstrapStatus = Field(...)
    missing_required: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _check(name: str, required: bool, kind: BootstrapCheckKind) -> BootstrapCheck:
    return BootstrapCheck(name=name, required=required, check_kind=kind)


def bootstrap_profile(host_id: str) -> tuple[BootstrapCheck, ...]:
    """Return the ordered readiness checklist for ``host_id``.

    Pure and deterministic: same ``host_id`` always yields the same tuple.
    ``host_id`` must be kebab-case (mirrors ``hosts.HostProfile``); the
    value is validated but otherwise unused — the checklist is host-generic.
    Order (fixed):

    1. ``python-version`` (required, version-window ``>=3.11``)
    2. ``package-installed`` (required, presence)
    3. ``core-importable`` (required, presence)
    4. ``policy-present`` (required, presence)
    5. ``mcp-adapter-present`` (optional, presence — stdio works without it)
    6. ``progress-recovery-present`` (optional, presence)
    7. ``config-present`` (optional, presence — MISSING still runs degraded)
    8. ``resources-present`` (required, presence)
    """
    if not _ID_RE.match(host_id):
        raise ValueError("host_id must be kebab-case")
    return (
        _check("python-version", True, BootstrapCheckKind.VERSION_WINDOW),
        _check("package-installed", True, BootstrapCheckKind.PRESENCE),
        _check("core-importable", True, BootstrapCheckKind.PRESENCE),
        _check("policy-present", True, BootstrapCheckKind.PRESENCE),
        _check("mcp-adapter-present", False, BootstrapCheckKind.PRESENCE),
        _check("progress-recovery-present", False, BootstrapCheckKind.PRESENCE),
        _check("config-present", False, BootstrapCheckKind.PRESENCE),
        _check("resources-present", True, BootstrapCheckKind.PRESENCE),
    )


def _normalize_checks(
    checks: Sequence[BootstrapCheck | Mapping[str, Any]],
) -> tuple[BootstrapCheck, ...]:
    normalized: list[BootstrapCheck] = []
    for item in checks:
        if isinstance(item, BootstrapCheck):
            normalized.append(item)
        elif isinstance(item, Mapping):
            normalized.append(BootstrapCheck.model_validate(dict(item)))
        else:
            raise TypeError(
                f"check must be BootstrapCheck or mapping, got {type(item).__name__}"
            )
    return tuple(normalized)


def evaluate(
    checks: Sequence[BootstrapCheck | Mapping[str, Any]],
    evidence: Mapping[str, Any],
) -> BootstrapEvaluation:
    """Fold caller-supplied ``evidence`` into a readiness verdict.

    ``evidence`` maps check ``name`` → fact (truthy = satisfied, falsy or
    absent = missing). No probing happens here. Output lists preserve the
    input ``checks`` order for determinism.

    - missing ``required`` check → ``BLOCKED`` (listed in ``missing_required``)
    - missing optional check → warning (listed in ``warnings``); if no
      required check is missing but warnings exist → ``DEGRADED``
    - nothing missing → ``READY``
    """
    normalized = _normalize_checks(checks)
    facts = dict(evidence)
    missing_required: list[str] = []
    warnings: list[str] = []
    for check in normalized:
        if not facts.get(check.name):
            if check.required:
                missing_required.append(check.name)
            else:
                warnings.append(check.name)
    if missing_required:
        status = BootstrapStatus.BLOCKED
    elif warnings:
        status = BootstrapStatus.DEGRADED
    else:
        status = BootstrapStatus.READY
    return BootstrapEvaluation(
        status=status,
        missing_required=tuple(missing_required),
        warnings=tuple(warnings),
    )
