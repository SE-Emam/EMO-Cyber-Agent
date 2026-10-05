"""Server-side capability-negotiation handshake — POST-T018 (Agent 4A).

Offer/accept/narrowing only. No execution, no shell, no policy mutation.

Protocol:
  1. Server proposes an ``offered`` set for a task kind (``propose_offer``).
  2. Host requests capabilities (``negotiate`` intersects request with offer).
  3. Granted = offered ∩ requested. Everything requested but not offered
     lands in ``denied`` with an explicit per-item reason — never silent.
  4. The outcome is a frozen ``NegotiationRecord`` with a deterministic
     ``negotiation_id`` + ``digest`` (same input → same record, replay-safe).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

SERVER_COMPUTED_BY = "core-policy"

SECURITY_REVIEW_OFFER: tuple[str, ...] = (
    "codeintel.read",
    "evidence.create",
    "evidence.read",
    "repo.read",
    "report.generate",
    "verification.safe",
)

TASK_OFFERS: dict[str, tuple[str, ...]] = {
    "security-review": SECURITY_REVIEW_OFFER,
}

KNOWN_CAPABILITIES: tuple[str, ...] = tuple(sorted(set(SECURITY_REVIEW_OFFER)))


def _normalize_tokens(items: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise HostIntegrationError(HostErrorCode.INVALID, "capability tokens must be non-empty strings")
        seen.add(item.strip())
    return tuple(sorted(seen))


def propose_offer(task_kind: str, *, server: bool = False) -> tuple[str, ...]:
    """Server-side offer for a task kind. ``server=True`` required (Core only)."""
    if not server:
        raise HostIntegrationError(
            HostErrorCode.CAPABILITY_DENIED,
            "capability offers must be proposed server-side",
        )
    if not task_kind or not task_kind.strip():
        raise HostIntegrationError(HostErrorCode.INVALID, "task_kind must be a non-empty string")
    key = task_kind.strip()
    if key not in TASK_OFFERS:
        raise HostIntegrationError(
            HostErrorCode.COMPAT_UNKNOWN,
            f"unknown task kind: {key}",
        )
    return TASK_OFFERS[key]


class NegotiationRecord(BaseModel):
    """Frozen, replay-safe outcome of one offer/accept round."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    negotiation_id: str = Field(min_length=1, max_length=120)
    digest: str = Field(min_length=16, max_length=128)
    task_kind: str = Field(min_length=1)
    offered: tuple[str, ...] = ()
    requested: tuple[str, ...] = ()
    granted: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    reason: str = Field(min_length=1)

    @field_validator("offered", "requested", "granted", "denied")
    @classmethod
    def _tokens(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for item in v:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("capability tokens must be non-empty strings")
        return v

    @classmethod
    def compute(
        cls,
        task_kind: str,
        offered: tuple[str, ...] | list[str],
        requested: tuple[str, ...] | list[str],
        *,
        server: bool = False,
    ) -> Self:
        """Server-only narrowing. Every non-granted request is denied with reason."""
        if not server:
            raise HostIntegrationError(
                HostErrorCode.CAPABILITY_DENIED,
                "negotiation must be computed server-side",
            )
        if not task_kind or not task_kind.strip():
            raise HostIntegrationError(HostErrorCode.INVALID, "task_kind must be a non-empty string")
        kind = task_kind.strip()
        offered_n = _normalize_tokens(tuple(offered))
        requested_n = _normalize_tokens(tuple(requested))

        offered_set = set(offered_n)
        granted = tuple(sorted(offered_set & set(requested_n)))
        denied = tuple(sorted(set(requested_n) - offered_set))

        reasons: list[str] = []
        for item in denied:
            if item not in KNOWN_CAPABILITIES:
                reasons.append(f"unknown-capability:{item}")
            else:
                reasons.append(f"not-offered:{item}")
        if not requested_n:
            reason = "empty-request:nothing granted"
        elif not denied:
            reason = "narrowing-accepted:all requested capabilities offered"
        else:
            reason = "withheld:" + ",".join(reasons)

        payload = {
            "task_kind": kind,
            "offered": list(offered_n),
            "requested": list(requested_n),
            "granted": list(granted),
            "denied": list(denied),
            "reason": reason,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        negotiation_id = f"nego-{digest[:16]}"
        return cls(
            negotiation_id=negotiation_id,
            digest=digest,
            task_kind=kind,
            offered=offered_n,
            requested=requested_n,
            granted=granted,
            denied=denied,
            reason=reason,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def negotiate(
    task_kind: str,
    requested: tuple[str, ...] | list[str],
    *,
    server: bool = False,
    offered: tuple[str, ...] | list[str] | None = None,
) -> NegotiationRecord:
    """Full handshake: propose the server offer for ``task_kind``, then narrow.

    ``offered`` may be supplied only to replay a prior offer; it must equal
    the server offer for the task kind (widening attempts are rejected).
    """
    if not server:
        raise HostIntegrationError(
            HostErrorCode.CAPABILITY_DENIED,
            "negotiation must run server-side",
        )
    server_offer = propose_offer(task_kind, server=True)
    if offered is not None:
        replayed = _normalize_tokens(tuple(offered))
        if set(replayed) != set(server_offer):
            raise HostIntegrationError(
                HostErrorCode.CAPABILITY_WIDENING,
                "replayed offer does not match server offer",
            )
        server_offer = tuple(sorted(replayed))
    return NegotiationRecord.compute(task_kind, server_offer, tuple(requested), server=True)
