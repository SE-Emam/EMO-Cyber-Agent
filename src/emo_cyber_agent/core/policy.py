"""Production-safe Policy Engine — ECA-T007 precondition.

Closes the ECA-T005/T006-documented gap where DefaultPolicyEngine was
allow-all. For REAL command execution this was unacceptable, so this module
provides option (A): a default-deny policy inside Core.

Deny rules (all deterministic, all audited via PolicyDecision):
- unknown capability = DENY
- unregistered tool/capability mismatch = DENY (enforced by callers via registry)
- missing explicit capability = DENY
- write/destructive/admin/network = DENY unless explicitly granted
- execution without a policy decision = DENY (enforced by ToolExecutor)

DefaultPolicyEngine is KEPT UNCHANGED for the read-only fact-collection
path (ECA-T005/T006 tests depend on its allow-all read behavior). The
execution path (ToolExecutor) REQUIRES StrictPolicyEngine and refuses to
run with any other engine type.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.core.contracts import PolicyEngine

POLICY_VERSION = "eca-t007-v1"

# Capabilities the strict engine knows. Anything else → DENY.
KNOWN_READ_CAPABILITIES: tuple[str, ...] = (
    "repository.read",
    "repository.list",
    "repository.search",
    "repository.metadata",
    "supabase.project.read",
    "supabase.schema.read",
    "supabase.table.read",
    "supabase.policy.read",
    "supabase.grant.read",
    "supabase.function.read",
    "supabase.view.read",
    "scanner.local.execute",
    "verification.static",
    "verification.config",
    "verification.read_query",
)

# scanner.network.read and verification.controlled_reproduction are known
# but NEVER in the default grant set (explicit grant required).
KNOWN_NETWORK_CAPABILITIES: tuple[str, ...] = ("scanner.network.read",)
KNOWN_RESTRICTED_CAPABILITIES: tuple[str, ...] = ("verification.controlled_reproduction",)

_WRITE_RE = re.compile(r"\b(write|admin|delete|drop|destroy|mutate|remediat|push|merge|deploy|migrate)\b", re.IGNORECASE)
_DESTRUCTIVE_RE = re.compile(r"\b(destruct|drop\b|delete\b|truncate|destroy|wipe)\b", re.IGNORECASE)


class PolicyDecision(BaseModel):
    """Auditable allow/deny record. Every execution decision leaves one."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: str = Field(..., min_length=1)
    requested_capability: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    allowed: bool = False
    profile: str = Field(default="read_only")
    reason_codes: tuple[str, ...] = Field(default_factory=tuple)
    constraints: dict[str, Any] = Field(default_factory=dict)
    issued_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy_version: str = Field(default=POLICY_VERSION)


class StrictPolicyEngine(PolicyEngine):
    """Default-deny gatekeeper for the execution path.

    `granted_network` / `granted_write`: explicit out-of-default grants
    (empty by default → network/write always denied). Every decision is
    recorded and retrievable for audit.
    """

    def __init__(
        self,
        *,
        granted_network: tuple[str, ...] = (),
        granted_write: tuple[str, ...] = (),
        granted_restricted: tuple[str, ...] = (),
        scope_allows: Any | None = None,
    ) -> None:
        self._granted_network = tuple(granted_network)
        self._granted_write = tuple(granted_write)
        self._granted_restricted = tuple(granted_restricted)
        self._scope_allows = scope_allows  # optional callable(audit_id, target) -> bool
        self._decisions: dict[str, PolicyDecision] = {}

    # -- decision log --
    @property
    def decisions(self) -> dict[str, PolicyDecision]:
        return dict(self._decisions)

    def get_decision(self, decision_id: str) -> PolicyDecision | None:
        return self._decisions.get(decision_id)

    # -- PolicyEngine interface (all deny-by-default) --
    def check_scope(self, audit_id: str, target: str) -> bool:
        if not audit_id or not target:
            return False
        if self._scope_allows is None:
            return True  # scope table enforced by services; engine checks shape only
        try:
            return bool(self._scope_allows(audit_id, target))
        except Exception:
            return False

    def check_capability(self, tool_id: str, capability: str) -> bool:
        if not tool_id or not capability:
            return False
        return capability in KNOWN_READ_CAPABILITIES or capability in self._granted_network or capability in KNOWN_NETWORK_CAPABILITIES and capability in self._granted_network

    def check_permission(self, profile: str, tool_id: str, risk_level: str, read_only: bool) -> bool:
        if profile not in ("read_only", "verify", "remediate"):
            return False
        if profile == "read_only" and not read_only:
            return False
        if _DESTRUCTIVE_RE.search(risk_level or ""):
            return False
        return True

    def check_target(self, target: str) -> bool:
        return bool(target and target.strip())

    def classify_content(self, content: str) -> str:
        # Repository/DB content is data. Never promoted by classification.
        if any(k in content.lower() for k in ("exec(", "eval(", "system(", "subprocess.", "drop table", "ignore previous")):
            return "untrusted-potential-instruction"
        return "untrusted-data"

    def evaluate_policy(self, audit_id: str, tool_id: str, target: str, profile: str, capabilities: list[str]) -> bool:
        decision = self.issue_decision(audit_id, tool_id, target, profile, capabilities)
        return decision.allowed

    # -- core gate --
    def issue_decision(self, audit_id: str, tool_id: str, target: str, profile: str, capabilities: list[str]) -> PolicyDecision:
        reasons: list[str] = []
        allowed = True

        if not audit_id or not tool_id or not target:
            allowed, reasons = False, ["missing-context"]
        elif not capabilities:
            allowed, reasons = False, ["missing-explicit-capability"]
        else:
            for cap in capabilities:
                if cap not in KNOWN_READ_CAPABILITIES and cap not in KNOWN_NETWORK_CAPABILITIES and cap not in KNOWN_RESTRICTED_CAPABILITIES:
                    allowed = False
                    reasons.append(f"unknown-capability:{cap}")
                elif cap in KNOWN_NETWORK_CAPABILITIES and cap not in self._granted_network:
                    allowed = False
                    reasons.append(f"network-not-granted:{cap}")
                elif cap in KNOWN_RESTRICTED_CAPABILITIES and cap not in self._granted_restricted:
                    allowed = False
                    reasons.append(f"restricted-not-granted:{cap}")
                elif _WRITE_RE.search(cap) and cap not in self._granted_write:
                    allowed = False
                    reasons.append(f"write-not-granted:{cap}")
            if profile not in ("read_only", "verify"):
                allowed = False
                reasons.append(f"profile-denied:{profile}")
            if self._scope_allows is not None and allowed:
                try:
                    if not self._scope_allows(audit_id, target):
                        allowed = False
                        reasons.append("out-of-scope")
                except Exception:
                    allowed = False
                    reasons.append("scope-check-failed")
        if allowed and not reasons:
            reasons = ["default-read-allow"]

        decision = PolicyDecision(
            audit_id=audit_id or "missing",
            requested_capability=",".join(capabilities) if capabilities else "none",
            target=target or "missing",
            allowed=allowed,
            profile=profile,
            reason_codes=tuple(reasons),
            constraints={"tool_id": tool_id},
        )
        self._decisions[decision.decision_id] = decision
        return decision
