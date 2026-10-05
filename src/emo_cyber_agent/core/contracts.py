"""Core contracts for EMO-Cyber-Agent.

Defines the abstract interfaces that adapters must use to interact
with the Core domain. Adapters MUST NOT contain security logic;
they translate requests/results only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from emo_cyber_agent.domain.models import AuditResult


class PolicyEngine(ABC):
    """Gatekeeper for all tool invocations.

    The Policy Engine is the final authority on whether an action may execute.
    The model proposes actions; the Policy Engine decides.
    """

    @abstractmethod
    def check_scope(self, audit_id: str, target: str) -> bool:
        """Verify the target is within the audit scope."""
        ...

    @abstractmethod
    def check_capability(self, tool_id: str, capability: str) -> bool:
        """Verify the tool has the required capability."""
        ...

    @abstractmethod
    def check_permission(self, profile: str, tool_id: str, risk_level: str, read_only: bool) -> bool:
        """Verify the permission profile allows the action."""
        ...

    @abstractmethod
    def check_target(self, target: str) -> bool:
        """Verify the target is allowed under current policy."""
        ...

    @abstractmethod
    def classify_content(self, content: str) -> str:
        """Classify repository content as trusted or untrusted."""
        ...

    @abstractmethod
    def evaluate_policy(self, audit_id: str, tool_id: str, target: str, profile: str, capabilities: list[str]) -> bool:
        """Evaluate whether a tool invocation is allowed."""
        ...


class EvidenceStore(ABC):
    """Normalized evidence storage with full provenance."""

    @abstractmethod
    def store(self, evidence: Any) -> str:
        """Store an evidence item and return its ID."""
        ...

    @abstractmethod
    def retrieve(self, evidence_id: str) -> Any | None:
        """Retrieve an evidence item by ID."""
        ...

    @abstractmethod
    def link_to_finding(self, evidence_id: str, finding_id: str) -> None:
        """Link an evidence item to a finding."""
        ...


class SecurityAuditor(ABC):
    """Public contract for the security audit service.

    All adapters (MCP, CLI, Python API) call this same interface.
    The Core owns the security investigation workflow after delegation.
    """

    @abstractmethod
    async def audit(self, target: str, mode: str = "standard", permission_profile: str = "read_only", **kwargs: Any) -> AuditResult:
        """Run a full or scoped security audit."""
        ...

    @abstractmethod
    async def review(self, target: str, focus: list[str] | None = None, **kwargs: Any) -> AuditResult:
        """Run a focused review of provided code/context."""
        ...

    @abstractmethod
    async def verify(self, finding_id: str, permission_profile: str = "read_only", **kwargs: Any) -> AuditResult:
        """Verify a specific finding using only policy-approved actions."""
        ...

    @abstractmethod
    async def doctor(self) -> dict[str, Any]:
        """Return runtime capability status without exposing credentials."""
        ...