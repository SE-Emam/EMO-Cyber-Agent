"""Server-side capability minimization — POST-T018 (Agent 4B).

Least-privilege narrowing gate. :func:`minimize` intersects a requested set
with the server allow-set, subtracts explicit denies, and enforces a
default-deny policy for privileged categories (write / destructive / admin /
network / remediation). Privileged capabilities are NEVER granted unless
explicitly present in the server allowlist — and even then never beyond
``allowed`` and never when explicitly ``denied``.

Read-only → write escalation (requesting a write-flavoured capability on a
scope the server only offered as read-only) and scope widening (requesting
anything outside ``allowed``) are rejected with an explicit per-item reason —
never silent.

Pure function, deterministic (same input → same output regardless of input
ordering), no execution: no I/O, no shell, no policy mutation.
"""

from __future__ import annotations

import json
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

# Privileged categories subject to default-deny. A requested capability whose
# (case-insensitive) token contains any marker is privileged and is granted
# only when explicitly present in the server allowlist.
PRIVILEGED_CATEGORIES: dict[str, tuple[str, ...]] = {
    "write": ("write",),
    "destructive": ("delete", "destroy", "destructive", "wipe"),
    "admin": ("admin", "root"),
    "network": ("network", "egress", "ingress"),
    "remediation": ("remediat",),
}

# Default-deny: by default no privileged capability is allowlisted.
DEFAULT_SERVER_ALLOWLIST: tuple[str, ...] = ()

TokenSequence = tuple[str, ...] | list[str] | set[str] | frozenset[str]


def privilege_category(token: str) -> str | None:
    """Return the privileged category for ``token``, or None if unprivileged."""
    lowered = token.lower()
    for category, markers in PRIVILEGED_CATEGORIES.items():
        if any(marker in lowered for marker in markers):
            return category
    return None


def is_privileged(token: str) -> bool:
    """Return True when ``token`` falls under default-deny."""
    return privilege_category(token) is not None


def _normalize_tokens(items: TokenSequence, *, label: str) -> tuple[str, ...]:
    if isinstance(items, (str, bytes)) or not isinstance(items, (tuple, list, set, frozenset)):
        raise HostIntegrationError(HostErrorCode.INVALID, f"{label} must be a sequence of capability tokens")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise HostIntegrationError(HostErrorCode.INVALID, "capability tokens must be non-empty strings")
        seen.add(item.strip())
    return tuple(sorted(seen))


def _scope(token: str) -> str:
    for sep in (".", ":", "/"):
        if sep in token:
            return token.split(sep, 1)[0]
    return token


def _is_read_only(token: str) -> bool:
    lowered = token.lower()
    return ("read" in lowered or "safe" in lowered) and privilege_category(token) is None


def _is_escalation(token: str, allowed: set[str]) -> bool:
    """True when ``token`` upgrades a read-only offered scope to a higher privilege."""
    if token in allowed:
        return False
    if privilege_category(token) is None and _is_read_only(token):
        return False  # read-flavoured request elsewhere is widening, not escalation
    scope = _scope(token)
    return any(_scope(candidate) == scope and _is_read_only(candidate) for candidate in allowed)


class MinimizationResult(BaseModel):
    """Frozen outcome of one minimization. Effective ⊆ requested ∩ allowed, ∩ denied = ∅."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    effective: tuple[str, ...] = ()
    rejected: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    reason: str = Field(min_length=1)
    requested: tuple[str, ...] = ()
    allowed: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    server_allowlist: tuple[str, ...] = ()

    @field_validator("effective", "rejected", "requested", "allowed", "denied", "server_allowlist")
    @classmethod
    def _tokens(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for item in v:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("capability tokens must be non-empty strings")
        return v

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        effective = set(self.effective)
        requested = set(self.requested)
        if not effective <= requested:
            raise ValueError("effective capabilities must be a subset of requested (narrowing-only)")
        if not effective <= set(self.allowed):
            raise ValueError("effective capabilities must be a subset of allowed (no widening)")
        if effective & set(self.denied):
            raise ValueError("effective capabilities must not intersect denied")
        if set(self.rejected) != requested - effective:
            raise ValueError("rejected must equal requested minus effective")
        if len(self.reasons) != len(self.rejected):
            raise ValueError("one reason required per rejected capability")
        for token, entry in zip(self.rejected, self.reasons, strict=True):
            if token not in entry:
                raise ValueError("every rejected capability needs an explicit reason")
        for token in self.rejected:
            if token not in self.reason:
                raise ValueError("rejections must never be silent: reason must name each rejected token")
        return self

    def allows(self, capability: str) -> bool:
        return capability in set(self.effective)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def minimize(
    requested: TokenSequence,
    allowed: TokenSequence,
    denied: TokenSequence,
    *,
    server_allowlist: TokenSequence = (),
) -> MinimizationResult:
    """Narrow ``requested`` to the least-privilege effective set.

    effective = (requested ∩ allowed) − denied − (privileged ∖ allowlist).

    Escalation (read-only → write on an offered scope) and scope widening
    (anything outside ``allowed``) are rejected with an explicit per-item
    reason. Deterministic: input ordering never affects the output.
    """
    req = _normalize_tokens(requested, label="requested")
    allow = _normalize_tokens(allowed, label="allowed")
    den = _normalize_tokens(denied, label="denied")
    allowlist = _normalize_tokens(server_allowlist, label="server_allowlist")

    allow_set = set(allow)
    denied_set = set(den)
    allowlist_set = set(allowlist)

    effective: list[str] = []
    rejected: list[str] = []
    reasons: list[str] = []
    for token in req:  # ``req`` is sorted → deterministic iteration
        if token in denied_set:
            rejected.append(token)
            reasons.append(f"denied:{token}")
        elif token not in allow_set and _is_escalation(token, allow_set):
            rejected.append(token)
            reasons.append(f"escalation:read-only-to-write:{token}")
        elif (category := privilege_category(token)) is not None and token not in allowlist_set:
            rejected.append(token)
            reasons.append(f"default-deny:{category}:{token}")
        elif token not in allow_set:
            rejected.append(token)
            reasons.append(f"scope-widening:{token}")
        else:
            effective.append(token)

    if not req:
        reason = "empty-request:nothing granted"
    elif not rejected:
        reason = "narrowing-accepted:all requested capabilities allowed"
    else:
        reason = "withheld:" + ",".join(reasons)

    return MinimizationResult(
        effective=tuple(effective),
        rejected=tuple(rejected),
        reasons=tuple(reasons),
        reason=reason,
        requested=req,
        allowed=allow,
        denied=den,
        server_allowlist=allowlist,
    )
