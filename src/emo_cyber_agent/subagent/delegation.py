"""Delegation pipeline — POST-T018.

Binds a :class:`TaskEnvelope` (delegation *request*) plus a server-issued
:class:`DelegationContext` (delegation *authorization*) to a
:class:`PolicyEngine` check.

Pipeline stages: parse → normalize → validate → scope-bind → policy decision.

Security invariants (fail-closed, deterministic, side-effect free):

- Delegation metadata NEVER becomes authority. Authorization derives only
  from the server-issued ``DelegationContext`` (issuer allow-list +
  ``authz-`` token + validity window + audience binding) and from the
  ``PolicyEngine`` verdict. Envelope text/capabilities/scope are untrusted
  input: they can narrow a grant, never widen or mint one.
- No execution, no shell, no policy mutation. This module never spawns
  processes, never evaluates code, and never mutates the engine — it only
  *reads* via ``PolicyEngine.evaluate_policy``.
- Hostile payloads embedded in delegation metadata are denied with reasons;
  cross-audit / scope mismatch quarantines.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Self

from pydantic import BaseModel, ConfigDict

from emo_cyber_agent.core.contracts import PolicyEngine
from emo_cyber_agent.subagent.capabilities import (
    CapabilityEnvelope,
    EffectiveCapabilitySet,
)
from emo_cyber_agent.subagent.envelope import (
    DelegatedScope,
    DelegationContext,
    TaskEnvelope,
    assert_authorization_independent,
)
from emo_cyber_agent.subagent.trust import (
    DelegationSecurityDecision,
    HostErrorCode,
    HostIntegrationError,
    SecurityDecision,
    scan_secret_markers,
)

try:  # Reuse the shared sanitizer normalizer so both screens agree (M2).
    from emo_cyber_agent.subagent.sanitizer import normalize as _sanitizer_normalize
except Exception:  # pragma: no cover - fallback inline NFKC when sanitizer unavailable
    _sanitizer_normalize = None  # type: ignore[assignment]

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_WS_RE = re.compile(r"\s+")

# Filler words tolerated between a hostile verb and its object (H1).
# Covers "hide ALL/THE findings", "hide all of the findings", "hide-the-findings".
# Separators include whitespace, hyphens and underscores so hyphen/underscore
#-joined evasions match after NFKC/lowercase/whitespace-collapse normalization.
_FILLER = r"(?:all|the|these|those|any|my|our|your|of)[\s\-_]+"

# Hostile payload classes. Keys are canonical labels; each maps to patterns
# matched against normalized (NFKC, lowercased, whitespace-collapsed) untrusted text.
# Every canonical example string from the spec matches its class pattern.
# The hide-finding / grant-write families tolerate filler words and
# inflections; role-confusion / system-message mirror sanitizer classes (M2).
HOSTILE_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "ignore policy": (
        re.compile(r"ignore\s+(the\s+|all\s+)?polic"),
        # G11-M1: generalized disregard family — mirrors sanitizer (lowercased
        # input here, so no IGNORECASE needed).
        re.compile(
            r"dis[\s\-_]*regard[\s\-_/]+"
            r"(the[\s\-_/]+|all[\s\-_/]+|any[\s\-_/]+)?"
            r"(polic\w*|previous|prior|above|instructions?\b)"
        ),
        # G11-M1: do-not family — hyphen/concat-tolerant with
        # verify/validate/check verbs; mirrors sanitizer.
        re.compile(r"do[\s\-_]*not[\s\-_]*(verif\w*|validat\w*|check\w*)"),
    ),
    "grant write": (
        re.compile(r"\bgrant(?:ed|ing|s)?\b.{0,40}\bwrite\b"),
        re.compile(r"\bgrant(?:ed|ing|s)?\b.{0,40}\bpermission\b"),
        re.compile(r"\bescalat\w*"),
    ),
    "disable verification": (
        re.compile(r"disabl\w*\s+verif"),
        re.compile(r"\b(skip|bypass)\w*\s+verif"),
    ),
    "hide finding": (
        re.compile(rf"\bhid\w*[\s\-_]+(?:{_FILLER})*findings?\b"),
        re.compile(rf"\b(suppress|drop|omit|delete)\w*[\s\-_]+(?:{_FILLER})*findings?\b"),
        re.compile(r"mark\s+finding\s+confirmed"),
    ),
    "use another audit": (
        re.compile(r"use\s+another\s+audit"),
        re.compile(r"cross[\s\-_]*audit"),
        re.compile(r"\bother\s+audit\b"),
        re.compile(r"\bswitch\s+audits?\b"),
    ),
    "fake approval": (
        re.compile(r"fake\s+approv"),
        re.compile(r"forg\w*\s+approv"),
        re.compile(r"self[\s\-_]*approv"),
        re.compile(r"auto[\s\-_]*approv"),
    ),
    "system message": (
        re.compile(r"system\s+message"),
        re.compile(r"developer\s+instruction"),
        re.compile(r"security\s+override"),
        re.compile(r"\btrust\s+me\b"),
    ),
    "role confusion": (
        re.compile(r"you\s+are\s+(now\s+)?(system|developer|admin(?:istrator)?|root)\b"),
        re.compile(r"act\s+as\s+(system|admin(?:istrator)?|root|developer)\b"),
        re.compile(r"pretend\s+(to\s+be|you\s+are)\b"),
        re.compile(r"new\s+role\s+is\b"),
    ),
}

HOSTILE_CLASSES: tuple[str, ...] = tuple(sorted(HOSTILE_PATTERNS))

# Cross-audit-flavoured hostile attempts quarantine rather than merely deny.
_QUARANTINE_HOSTILE_CLASSES: frozenset[str] = frozenset({"use another audit"})

_READ_ONLY_PROFILE = "read_only"


def normalize_text(text: str) -> str:
    """Deterministic normalization for hostile-payload scanning.

    NFKC (via the shared sanitizer normalizer when importable, else inline
    NFKC fallback — NOTE) → lowercase → whitespace-collapse.
    """
    raw = text or ""
    if _sanitizer_normalize is not None:
        try:
            raw = _sanitizer_normalize(raw)
        except Exception:
            raw = unicodedata.normalize("NFKC", raw)
    else:  # NOTE: fallback path when sanitizer import failed; same NFKC semantics
        raw = unicodedata.normalize("NFKC", raw)
    return _WS_RE.sub(" ", raw.lower()).strip()


def collect_untrusted_text(envelope: TaskEnvelope) -> str:
    """Join every envelope field that originates outside Core.

    Delegation metadata is untrusted by construction: task description,
    assets, requested outputs, scope strings and *requested* capabilities.
    """
    parts: list[str] = [envelope.requested_task]
    parts.extend(envelope.assets)
    parts.extend(envelope.requested_output)
    parts.extend(envelope.scope.included)
    parts.extend(envelope.scope.excluded)
    parts.extend(envelope.scope.target_types)
    parts.extend(envelope.capabilities)
    return "\n".join(p for p in parts if p)


def scan_hostile(normalized_text: str) -> tuple[str, ...]:
    """Return sorted hostile-class labels hit in normalized text (pure)."""
    hits: list[str] = []
    for label in HOSTILE_CLASSES:
        for pattern in HOSTILE_PATTERNS[label]:
            if pattern.search(normalized_text):
                hits.append(label)
                break
    return tuple(hits)


def parse_envelope(data: dict[str, Any]) -> TaskEnvelope:
    """Parse raw mapping into a TaskEnvelope (raises on invalid input)."""
    return TaskEnvelope.model_validate(data)


def delegation_target(envelope: TaskEnvelope) -> str:
    """Deterministic policy-check target derived from delegation metadata."""
    if envelope.scope.included:
        return envelope.scope.included[0]
    if envelope.assets:
        return envelope.assets[0]
    return envelope.requested_task or envelope.host_id


class DelegationOutcome(BaseModel):
    """Result of one DelegationPipeline evaluation. Records; permits nothing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: DelegationSecurityDecision
    effective: EffectiveCapabilitySet | None = None
    policy_allowed: bool = False

    @property
    def is_allow(self) -> bool:
        return self.decision.decision == SecurityDecision.ALLOW and self.policy_allowed

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _deny(reason: str, *, now: int) -> DelegationOutcome:
    return DelegationOutcome(
        decision=DelegationSecurityDecision(
            decision=SecurityDecision.DENY,
            reasons=(reason,),
            evaluated_at=now,
        ),
        effective=None,
        policy_allowed=False,
    )


def _quarantine(reason: str, *, now: int) -> DelegationOutcome:
    return DelegationOutcome(
        decision=DelegationSecurityDecision(
            decision=SecurityDecision.QUARANTINE,
            reasons=(reason,),
            evaluated_at=now,
        ),
        effective=None,
        policy_allowed=False,
    )


class DelegationPipeline:
    """Server-side delegation gate. Read-only w.r.t. the policy engine.

    ``allowed_capabilities`` / ``denied_capabilities`` and ``outer_scope``
    are server-provided bounds: the effective grant is always narrowed to
    ``requested ∩ allowed − denied`` and to within ``outer_scope``.
    """

    def __init__(
        self,
        policy: PolicyEngine,
        *,
        allowed_capabilities: tuple[str, ...] | list[str],
        denied_capabilities: tuple[str, ...] | list[str] = (),
        outer_scope: DelegatedScope | None = None,
        policy_version: str = "1.0.0",
    ) -> None:
        if not _SEMVER_RE.match(policy_version):
            raise ValueError("policy_version must be semver X.Y.Z")
        self._policy = policy
        self._allowed = tuple(allowed_capabilities)
        self._denied = tuple(denied_capabilities)
        self._outer_scope = outer_scope
        self._policy_version = policy_version

    @property
    def allowed_capabilities(self) -> tuple[str, ...]:
        return self._allowed

    @property
    def denied_capabilities(self) -> tuple[str, ...]:
        return self._denied

    def evaluate(
        self,
        envelope: TaskEnvelope,
        context: DelegationContext,
        *,
        now: int,
        audit_id: str,
        project_id: str,
        snapshot_id: str,
    ) -> DelegationOutcome:
        """Run parse → normalize → validate → scope-bind → policy decision."""
        # -- parse: typed inputs only; anything else is fail-closed DENY --
        if not isinstance(envelope, TaskEnvelope) or not isinstance(context, DelegationContext):
            return _deny("invalid: delegation inputs must be typed envelope+context", now=now)

        # -- normalize: untrusted delegation metadata, deterministically --
        raw_text = collect_untrusted_text(envelope)
        normalized = normalize_text(raw_text)

        # -- validate: authorization comes only from context + engine --
        try:
            assert_authorization_independent(context.authorization_ref, raw_text)
        except HostIntegrationError as exc:
            return _deny(f"authz-forged: {exc}", now=now)
        if scan_secret_markers(raw_text):
            return _quarantine("secret markers observed in delegation metadata", now=now)
        try:
            context.assert_authorized_for(envelope, now=now)
        except HostIntegrationError as exc:
            if exc.code == HostErrorCode.EXPIRED:
                return _deny(f"expired: {exc}", now=now)
            return _deny(f"authz-forged: {exc}", now=now)

        # -- scope-bind: audit/project/snapshot + narrowing-only scope --
        try:
            envelope.assert_binding(audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id)
        except HostIntegrationError as exc:
            return _quarantine(f"binding-mismatch: {exc}", now=now)
        if self._outer_scope is not None:
            try:
                envelope.assert_scope_within(self._outer_scope)
            except HostIntegrationError as exc:
                return _quarantine(f"scope-widening: {exc}", now=now)

        # -- hostile-payload screen: metadata can never authorize itself --
        hits = scan_hostile(normalized)
        if hits:
            reasons = tuple(f"hostile:{label}" for label in hits)
            if any(label in _QUARANTINE_HOSTILE_CLASSES for label in hits):
                return DelegationOutcome(
                    decision=DelegationSecurityDecision(
                        decision=SecurityDecision.QUARANTINE,
                        reasons=reasons,
                        evaluated_at=now,
                    ),
                    effective=None,
                    policy_allowed=False,
                )
            return DelegationOutcome(
                decision=DelegationSecurityDecision(
                    decision=SecurityDecision.DENY,
                    reasons=reasons,
                    evaluated_at=now,
                ),
                effective=None,
                policy_allowed=False,
            )

        # -- policy decision: server-computed narrowing + engine check --
        cap_envelope = CapabilityEnvelope(
            audit_id=audit_id,
            project_id=project_id,
            snapshot_id=snapshot_id,
            requested=envelope.capabilities,
            allowed=self._allowed,
            denied=self._denied,
            inherited=(),
        )
        try:
            effective = EffectiveCapabilitySet.compute(
                cap_envelope,
                policy_version=self._policy_version,
                computed_at=now,
                server=True,  # this pipeline IS the server-side Core path
            )
        except (HostIntegrationError, ValueError) as exc:
            return _deny(f"capability-denied: {exc}", now=now)
        if not effective.effective:
            return _deny("capability-denied: empty effective grant", now=now)

        try:
            policy_allowed = bool(
                self._policy.evaluate_policy(
                    audit_id,
                    envelope.host_id,
                    delegation_target(envelope),
                    _READ_ONLY_PROFILE,
                    list(effective.effective),
                )
            )
        except Exception as exc:  # fail closed on engine errors
            return _deny(f"policy-denied: engine error: {exc}", now=now)
        if not policy_allowed:
            return DelegationOutcome(
                decision=DelegationSecurityDecision(
                    decision=SecurityDecision.DENY,
                    reasons=("policy-denied: engine refused delegation",),
                    evaluated_at=now,
                ),
                effective=None,
                policy_allowed=False,
            )
        return DelegationOutcome(
            decision=DelegationSecurityDecision(
                decision=SecurityDecision.ALLOW,
                reasons=("narrow-delegation-authorized",),
                evaluated_at=now,
            ),
            effective=effective,
            policy_allowed=True,
        )

    def evaluate_raw(
        self,
        data: dict[str, Any],
        context: DelegationContext,
        *,
        now: int,
        audit_id: str,
        project_id: str,
        snapshot_id: str,
    ) -> DelegationOutcome:
        """Parse-then-evaluate convenience wrapper (parse failures → DENY)."""
        try:
            envelope = parse_envelope(data)
        except Exception as exc:
            return _deny(f"invalid: cannot parse delegation envelope: {exc}", now=now)
        return self.evaluate(
            envelope,
            context,
            now=now,
            audit_id=audit_id,
            project_id=project_id,
            snapshot_id=snapshot_id,
        )
