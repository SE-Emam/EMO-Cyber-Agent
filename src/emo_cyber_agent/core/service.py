"""Application service facade.

Implements the SecurityAuditor and PolicyEngine contracts for Phase 2 Tool Registry.
Core domain logic lives in domain models and contracts; adapters remain thin.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.core.contracts import PolicyEngine, SecurityAuditor
from emo_cyber_agent.domain.models import AuditJob, AuditResult


class DefaultPolicyEngine(PolicyEngine):
    """Default read-only policy engine for foundation."""

    def check_scope(self, audit_id: str, target: str) -> bool:
        return True

    def check_capability(self, tool_id: str, capability: str) -> bool:
        return True

    def check_permission(self, profile: str, tool_id: str, risk_level: str, read_only: bool) -> bool:
        if profile == "read_only" and not read_only:
            return False
        if profile == "remediate" and not read_only:
            return False
        return True

    def check_target(self, target: str) -> bool:
        if not target:
            return False
        return True

    def classify_content(self, content: str) -> str:
        if any(
            keyword in content.lower()
            for keyword in ["exec(", "eval(", "system(", "subprocess."]
        ):
            return "potential-instruction"
        return "code-or-data"

    def evaluate_policy(
        self,
        audit_id: str,
        tool_id: str,
        target: str,
        profile: str,
        capabilities: list[str],
    ) -> bool:
        """Evaluate whether a tool invocation is allowed."""
        # For Phase 2, allow all invocations
        # Phase 3 will implement actual policy evaluation
        return True


class FoundationSecurityAuditor(SecurityAuditor):
    """Concrete SecurityAuditor for Phase 2 Foundation.

    All adapters (MCP, CLI, Python API) call this same interface.
    The Core owns the security investigation workflow after delegation.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self._policy_engine = policy_engine or DefaultPolicyEngine()
        from .tool_registry import ToolRegistry
        self._tool_registry = ToolRegistry()

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    @property
    def tool_registry(self):
        return self._tool_registry

    async def audit(
        self,
        target: str,
        mode: str = "standard",
        permission_profile: str = "read_only",
        **kwargs: Any,
    ) -> AuditResult:
        """Run a full or scoped security audit.

        Phase 2: Creates the audit job and returns a stub result.
        Phase 7+: Full orchestration loop.
        """
        job = AuditJob(
            target=target,
            mode=mode,
            permission_profile=permission_profile,
        )

        # Create an empty result for Phase 2
        result = AuditResult(
            audit_id=job.id,
            status=job.status,
            target=target,
            mode=mode,
            permission_profile=permission_profile,
        )
        return result

    async def review(
        self,
        target: str,
        focus: list[str] | None = None,
        **kwargs: Any,
    ) -> AuditResult:
        """Run a focused review of provided code/context.

        Phase 2: Stub only.
        Phase 8+: Full reasoning loop.
        """
        job = AuditJob(
            target=target,
            mode="standard",
            permission_profile="read_only",
        )
        result = AuditResult(
            audit_id=job.id,
            status=job.status,
            target=target,
            mode="standard",
            permission_profile="read_only",
        )
        return result

    async def verify(
        self,
        finding_id: str,
        permission_profile: str = "read_only",
        **kwargs: Any,
    ) -> AuditResult:
        """Verify a specific finding using only policy-approved actions.

        Phase 2: Stub only.
        Phase 9+: Full verification loop.
        """
        job = AuditJob(
            target="verification",
            mode="standard",
            permission_profile=permission_profile,
        )
        result = AuditResult(
            audit_id=job.id,
            status=job.status,
            target="verification",
            mode="standard",
            permission_profile=permission_profile,
        )
        return result

    async     def doctor(self) -> dict[str, Any]:
        """Return runtime capability status without exposing credentials."""
        return {
            "status": "foundation",
            "version": "0.1.0",
            "policy_engine": type(self._policy_engine).__name__,
            "domain_models_available": True,
            "capabilities": ["audit", "review", "verify", "doctor"],
        }