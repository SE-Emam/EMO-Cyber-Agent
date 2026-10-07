"""Agent-to-agent trust boundary gate — POST-T018.

Runtime Agent-A → Agent-B trust gate for nested delegation. Given a chain
of :class:`TrustEdge` hops, evaluates one deterministic verdict per call:

- nested delegation is depth-bounded (``MAX_DELEGATION_DEPTH``); deeper → DENY
- audience must match the receiving agent of each hop; mismatch → DENY
- validity window must cover ``now``; expired (or inverted) → DENY
- scope may only narrow along the chain; widening → DENY
- cross-audit / cross-project hop without fresh server-issued context → QUARANTINE

This module is a *gate*, not an authority: it returns a
:class:`DelegationSecurityDecision` record (reasons + timestamp) and permits
nothing by itself. There is no escalation path, no capability grant, no
execution, no I/O, no clock read — ``now`` is caller-supplied. Raising
variants (:func:`assert_edge` / :func:`assert_chain`) subclass
:class:`HostIntegrationError` so existing ``except HostIntegrationError``
boundaries keep working.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Any, Self, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.subagent.trust import (
    DelegationSecurityDecision,
    HostErrorCode,
    HostIntegrationError,
    SecurityDecision,
)

#: Maximum nested delegation depth. A direct delegation is depth 0; each
#: nested re-delegation adds one. Anything deeper fails closed with DENY.
MAX_DELEGATION_DEPTH = 3

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")


class TrustBoundaryCode(StrEnum):
    """Machine-readable trust-gate failure classes (stable strings)."""

    EMPTY_CHAIN = "TRUST_EMPTY_CHAIN"
    INVALID = "TRUST_INVALID"
    DEPTH_OVERFLOW = "TRUST_DEPTH_OVERFLOW"
    DEPTH_ORDER = "TRUST_DEPTH_ORDER"
    CHAIN_BROKEN = "TRUST_CHAIN_BROKEN"
    AUDIENCE_MISMATCH = "TRUST_AUDIENCE_MISMATCH"
    RECIPIENT_MISMATCH = "TRUST_RECIPIENT_MISMATCH"
    INVALID_WINDOW = "TRUST_INVALID_WINDOW"
    EXPIRED = "TRUST_EXPIRED"
    SCOPE_WIDENING = "TRUST_SCOPE_WIDENING"
    CROSS_BOUNDARY = "TRUST_CROSS_BOUNDARY"


# TrustBoundaryCode → (host-interop code, quarantine?, security decision).
_BOUNDARY_WIRING: dict[TrustBoundaryCode, tuple[HostErrorCode, bool, SecurityDecision]] = {
    TrustBoundaryCode.EMPTY_CHAIN: (HostErrorCode.INVALID, False, SecurityDecision.DENY),
    TrustBoundaryCode.INVALID: (HostErrorCode.INVALID, False, SecurityDecision.DENY),
    TrustBoundaryCode.DEPTH_OVERFLOW: (HostErrorCode.INVALID, False, SecurityDecision.DENY),
    TrustBoundaryCode.DEPTH_ORDER: (HostErrorCode.INVALID, False, SecurityDecision.DENY),
    TrustBoundaryCode.CHAIN_BROKEN: (HostErrorCode.BINDING_MISMATCH, False, SecurityDecision.DENY),
    TrustBoundaryCode.AUDIENCE_MISMATCH: (HostErrorCode.AUTHZ_FORGED, False, SecurityDecision.DENY),
    TrustBoundaryCode.RECIPIENT_MISMATCH: (HostErrorCode.AUTHZ_FORGED, False, SecurityDecision.DENY),
    TrustBoundaryCode.INVALID_WINDOW: (HostErrorCode.INVALID, False, SecurityDecision.DENY),
    TrustBoundaryCode.EXPIRED: (HostErrorCode.EXPIRED, False, SecurityDecision.DENY),
    TrustBoundaryCode.SCOPE_WIDENING: (HostErrorCode.SCOPE_WIDENING, False, SecurityDecision.DENY),
    TrustBoundaryCode.CROSS_BOUNDARY: (HostErrorCode.CROSS_AUDIT, True, SecurityDecision.QUARANTINE),
}


class TrustBoundaryError(HostIntegrationError):
    """Trust-gate failure. Fail closed; never carries usable authority."""

    def __init__(self, boundary: TrustBoundaryCode, message: str, *, reason: str = "") -> None:
        code, quarantine, decision = _BOUNDARY_WIRING[boundary]
        super().__init__(code, f"{boundary.value}: {message}", reason=reason, quarantine=quarantine)
        self.boundary = boundary
        self.decision = decision

    def requires_quarantine(self) -> bool:
        return self.decision == SecurityDecision.QUARANTINE


class TrustEdge(BaseModel):
    """One Agent-A → Agent-B delegation hop. Frozen; grants nothing.

    ``scope`` is the token set handed to ``to_agent`` at this hop;
    ``scope_ref`` is its opaque server-side binding. ``audit_id`` /
    ``project_id`` pin the hop to its home boundary: a hop whose boundary
    differs from its predecessor (or from the caller's expected boundary)
    is a cross-boundary hop and needs fresh server-issued context.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    from_agent: str = Field(...)
    to_agent: str = Field(...)
    delegation_depth: int = Field(ge=0)
    audience: str = Field(min_length=1, max_length=80)
    valid_from: int = Field(ge=0)
    valid_until: int = Field(ge=0)
    scope: tuple[str, ...] = ()
    scope_ref: str = Field(min_length=1, max_length=120)
    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)

    @field_validator("from_agent", "to_agent")
    @classmethod
    def _kebab(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("agent id must be kebab-case")
        return v

    @field_validator("scope")
    @classmethod
    def _scope_tokens(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for item in v:
            if not item or not item.strip():
                raise ValueError("scope tokens must be non-empty strings")
        return v

    def is_valid_at(self, now: int) -> bool:
        return self.valid_from <= now <= self.valid_until

    def narrows(self, outer: TrustEdge) -> bool:
        """True if this hop's scope fits inside the previous hop (narrowing only)."""
        return set(self.scope) <= set(outer.scope)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _deny(reason: str, *, now: int) -> DelegationSecurityDecision:
    return DelegationSecurityDecision(
        decision=SecurityDecision.DENY,
        reasons=(reason,),
        evaluated_at=now,
    )


def _quarantine(reason: str, *, now: int) -> DelegationSecurityDecision:
    return DelegationSecurityDecision(
        decision=SecurityDecision.QUARANTINE,
        reasons=(reason,),
        evaluated_at=now,
    )


def evaluate_edge(edge: TrustEdge, *, receiver: str, now: int) -> DelegationSecurityDecision:
    """Evaluate a single direct delegation hop against its receiver.

    Check order is fixed (depth → audience/recipient → window → expiry) so
    failures are deterministic. Anything but full pass returns DENY.
    """
    if not isinstance(edge, TrustEdge) or not isinstance(receiver, str) or not isinstance(now, int):
        return _deny("invalid: edge, receiver and now must be typed TrustEdge/str/int", now=now if isinstance(now, int) else 0)
    if edge.delegation_depth > MAX_DELEGATION_DEPTH:
        return _deny(
            f"depth-overflow: depth {edge.delegation_depth} exceeds max {MAX_DELEGATION_DEPTH}",
            now=now,
        )
    if edge.audience != receiver:
        return _deny(
            f"audience-mismatch: audience {edge.audience!r} does not match receiving agent {receiver!r}",
            now=now,
        )
    if edge.to_agent != receiver:
        return _deny(
            f"recipient-mismatch: to_agent {edge.to_agent!r} does not match receiving agent {receiver!r}",
            now=now,
        )
    if edge.valid_until < edge.valid_from:
        return _deny("invalid-window: validity window is empty or inverted", now=now)
    if not edge.is_valid_at(now):
        return _deny("expired: validity window does not cover now", now=now)
    return DelegationSecurityDecision(
        decision=SecurityDecision.ALLOW,
        reasons=("direct-delegation-authorized",),
        evaluated_at=now,
    )


def evaluate_chain(
    chain: Sequence[TrustEdge],
    *,
    receiver: str,
    now: int,
    has_fresh_context: bool = False,
    expected_audit_id: str | None = None,
    expected_project_id: str | None = None,
) -> DelegationSecurityDecision:
    """Evaluate a nested delegation chain hop by hop.

    ``chain`` is ordered root-first: ``chain[i].to_agent`` must equal
    ``chain[i+1].from_agent``, depths must strictly increase, and each hop's
    scope must be a subset of its predecessor's. The final hop must land on
    ``receiver``. Any hop crossing an audit/project boundary (between hops,
    or against ``expected_audit_id`` / ``expected_project_id`` when given)
    requires ``has_fresh_context`` — a fresh server-issued context for the
    new boundary — otherwise the verdict is QUARANTINE.

    Check order is fixed: shape → depth → audience/recipient → window →
    scope-narrowing → cross-boundary. First failure wins, deterministically.
    """

    def _now() -> int:
        return now if isinstance(now, int) else 0

    if not isinstance(chain, (list, tuple)) or not chain:
        return _deny("invalid: chain must be a non-empty list/tuple of TrustEdge", now=_now())
    if not isinstance(receiver, str) or not isinstance(now, int):
        return _deny("invalid: receiver and now must be str/int", now=_now())
    for edge in chain:
        if not isinstance(edge, TrustEdge):
            return _deny("invalid: chain members must be TrustEdge", now=now)

    # -- depth: every hop bounded, strictly deepening along the chain --
    for i, edge in enumerate(chain):
        if edge.delegation_depth > MAX_DELEGATION_DEPTH:
            return _deny(
                f"depth-overflow: hop {i} depth {edge.delegation_depth} exceeds max {MAX_DELEGATION_DEPTH}",
                now=now,
            )
    for i in range(1, len(chain)):
        if chain[i].delegation_depth <= chain[i - 1].delegation_depth:
            return _deny(
                f"depth-order: hop {i} depth {chain[i].delegation_depth} does not deepen "
                f"past hop {i - 1} depth {chain[i - 1].delegation_depth}",
                now=now,
            )

    # -- audience/recipient: each hop's audience is that hop's receiver --
    for i, edge in enumerate(chain):
        if edge.audience != edge.to_agent:
            return _deny(
                f"audience-mismatch: hop {i} audience {edge.audience!r} does not match "
                f"receiving agent {edge.to_agent!r}",
                now=now,
            )
    for i in range(1, len(chain)):
        if chain[i].from_agent != chain[i - 1].to_agent:
            return _deny(
                f"chain-discontinuity: hop {i} from_agent {chain[i].from_agent!r} does not "
                f"continue hop {i - 1} to_agent {chain[i - 1].to_agent!r}",
                now=now,
            )
    if chain[-1].to_agent != receiver or chain[-1].audience != receiver:
        return _deny(
            f"recipient-mismatch: final hop lands on {chain[-1].to_agent!r} "
            f"(audience {chain[-1].audience!r}), not receiving agent {receiver!r}",
            now=now,
        )

    # -- validity: every hop's window must be well-formed and cover now --
    for i, edge in enumerate(chain):
        if edge.valid_until < edge.valid_from:
            return _deny(f"invalid-window: hop {i} validity window is empty or inverted", now=now)
    for i, edge in enumerate(chain):
        if not edge.is_valid_at(now):
            return _deny(f"expired: hop {i} validity window does not cover now", now=now)

    # -- scope: may only narrow along the chain, never widen --
    for i in range(1, len(chain)):
        if not chain[i].narrows(chain[i - 1]):
            widened = sorted(set(chain[i].scope) - set(chain[i - 1].scope))
            return _deny(
                f"scope-widening: hop {i} exceeds hop {i - 1} scope by {widened}",
                now=now,
            )

    # -- cross-boundary: audit/project hop needs fresh server-issued context --
    crossed: str | None = None
    for i in range(1, len(chain)):
        if chain[i].audit_id != chain[i - 1].audit_id:
            crossed = f"hop {i} crosses audit {chain[i - 1].audit_id!r} -> {chain[i].audit_id!r}"
            break
        if chain[i].project_id != chain[i - 1].project_id:
            crossed = f"hop {i} crosses project {chain[i - 1].project_id!r} -> {chain[i].project_id!r}"
            break
    if crossed is None:
        final = chain[-1]
        if expected_audit_id is not None and final.audit_id != expected_audit_id:
            crossed = f"final hop audit {final.audit_id!r} != expected {expected_audit_id!r}"
        elif expected_project_id is not None and final.project_id != expected_project_id:
            crossed = f"final hop project {final.project_id!r} != expected {expected_project_id!r}"
    if crossed is not None and not has_fresh_context:
        return _quarantine(
            f"cross-boundary: {crossed} without fresh server-issued context",
            now=now,
        )

    return DelegationSecurityDecision(
        decision=SecurityDecision.ALLOW,
        reasons=("delegation-chain-authorized",),
        evaluated_at=now,
    )


def _is_known_code(prefix: str) -> bool:
    # `prefix in TrustBoundaryCode` raises TypeError on Python 3.11 for
    # non-member strings (allowed since 3.12); compare values explicitly.
    return any(prefix == member.value for member in TrustBoundaryCode)


def _raise_for(decision: DelegationSecurityDecision, code: TrustBoundaryCode, message: str) -> None:
    prefix = message.split(":", 1)[0].strip() if ":" in message else message
    boundary = TrustBoundaryCode(prefix) if _is_known_code(prefix) else code
    raise TrustBoundaryError(boundary, message)


def assert_edge(edge: TrustEdge, *, receiver: str, now: int) -> None:
    """Void check for a direct hop. Non-ALLOW raises :class:`TrustBoundaryError`."""
    decision = evaluate_edge(edge, receiver=receiver, now=now)
    if decision.decision != SecurityDecision.ALLOW:
        reason = decision.reasons[0] if decision.reasons else "denied"
        _raise_for(decision, TrustBoundaryCode.INVALID, reason)


def assert_chain(
    chain: Sequence[TrustEdge],
    *,
    receiver: str,
    now: int,
    has_fresh_context: bool = False,
    expected_audit_id: str | None = None,
    expected_project_id: str | None = None,
) -> None:
    """Void check for a chain. Non-ALLOW raises :class:`TrustBoundaryError`."""
    decision = evaluate_chain(
        chain,
        receiver=receiver,
        now=now,
        has_fresh_context=has_fresh_context,
        expected_audit_id=expected_audit_id,
        expected_project_id=expected_project_id,
    )
    if decision.decision != SecurityDecision.ALLOW:
        reason = decision.reasons[0] if decision.reasons else "denied"
        code = (
            TrustBoundaryCode.CROSS_BOUNDARY
            if decision.decision == SecurityDecision.QUARANTINE
            else TrustBoundaryCode.INVALID
        )
        _raise_for(decision, code, reason)
