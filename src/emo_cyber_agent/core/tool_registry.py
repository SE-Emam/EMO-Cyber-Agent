"""Tool Registry and Tool Invocation boundary for EMO-Cyber-Agent.

Provides tool discovery, registration, validation, and invocation lifecycle
as part of the Core domain. This is the security boundary for all tool
interactions in the system.

Architecture:
Tool registry is in Core (not tools/adapters) - single source of truth.
No scanner adapters or tool implementations here - only contracts.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ToolCategory(StrEnum):
    SCANNER = "scanner"
    SECRETS = "secrets"
    DEPENDENCY = "dependency"
    REPOSITORY = "repository"
    DATABASE = "database"
    NETWORK = "network"
    CLOUD = "cloud"
    VERIFICATION = "verification"
    OTHER = "other"

class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EvidenceBehavior(StrEnum):
    STORE = "store"
    IGNORE = "ignore"
    SUMMARIZE = "summarize"

class ToolStatus(StrEnum):
    REGISTERED = "registered"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"

class ToolInvocationStatus(StrEnum):
    REQUESTED = "requested"
    VALIDATING = "validating"
    POLICY_CHECK = "policy_check"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"
    TIMEOUT = "timeout"


# ---------------------------------------------------------------------------
# Core Tool Models
# ---------------------------------------------------------------------------

class ToolSpec(BaseModel):
    """Tool specification - Core contract for all tools.

    This is the single source of truth for tool capabilities and constraints.
    Part of Core domain - no adapter-specific logic here.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Core identification
    tool_id: str = Field(..., min_length=1, description="Unique tool identifier")
    name: str = Field(..., min_length=1, description="Human-readable tool name")
    version: str = Field(..., min_length=1, description="Tool version")
    description: str = Field(..., min_length=1, description="Tool description")

    # Classification
    category: ToolCategory = Field(..., description="Tool category")
    risk_level: RiskLevel = Field(..., description="Risk classification")

    # Capabilities
    capabilities_required: tuple[str, ...] = Field(
        ..., description="Required capabilities for execution"
    )

    # Permissions
    supports_read_only: bool = Field(default=True, description="Supports read-only execution")
    supports_verification: bool = Field(default=False, description="Supports verification")
    supports_remediation: bool = Field(default=False, description="Supports remediation")

    # Target constraints
    target_types: tuple[str, ...] = Field(
        default=("repo", "project"), description="Types of targets supported"
    )
    input_schema: dict[str, Any] = Field(
        default_factory=dict, description="JSON Schema for tool input"
    )
    output_schema: dict[str, Any] | None = Field(
        default=None, description="JSON Schema for tool output"
    )

    # Execution constraints
    evidence_behavior: EvidenceBehavior = Field(
        default=EvidenceBehavior.SUMMARIZE, description="How tool output is handled"
    )
    timeout_ms: int | None = Field(default=None, ge=0, description="Maximum execution time")
    max_retries: int = Field(default=0, ge=0, description="Maximum retry attempts")
    concurrent_executions: int = Field(default=1, ge=1, description="Concurrent execution limit")

    # Metadata
    provenance: dict[str, Any] = Field(default_factory=dict, description="Source provenance")
    tags: tuple[str, ...] = Field(default_factory=tuple, description="Tool tags")
    documentation_url: str | None = Field(default=None, description="Documentation URL")
    contact: str | None = Field(default=None, description="Contact information")

    @field_validator("tool_id")
    @classmethod
    def tool_id_valid(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("tool_id must be non-empty")
        return v

    @field_validator("capabilities_required")
    @classmethod
    def capabilities_not_empty(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("tools must declare at least one required capability")
        return v

    @field_validator("target_types")
    @classmethod
    def target_types_not_empty(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("tools must declare supported target types")
        return v

    @model_validator(mode="after")
    def _validate_risk_and_permission_match(self) -> ToolSpec:
        if self.risk_level == RiskLevel.CRITICAL and not self.supports_remediation:
            raise ValueError("CRITICAL risk tools must support remediation")
        if self.risk_level == RiskLevel.HIGH and not self.supports_verification:
            raise ValueError("HIGH risk tools must support verification")
        if self.risk_level == RiskLevel.LOW and self.supports_remediation:
            raise ValueError("LOW risk tools should not support remediation")
        return self


class ToolInvocation(BaseModel):
    """Immutable record of a tool execution with full lifecycle.

    Part of Core domain - tracks all tool invocations through the security boundary.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Core identification
    invocation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: str = Field(..., min_length=1, description="Associated audit job")
    tool_id: str = Field(..., min_length=1, description="Tool being invoked")
    tool_version: str = Field(default="", description="Tool version at invocation time")

    # Invocation context
    target: str = Field(..., min_length=1, description="Target being scanned")
    requested_capabilities: tuple[str, ...] = Field(
        default_factory=tuple, description="Capabilities requested by the caller"
    )
    policy_decision_id: str = Field(default="", description="Policy decision reference")
    profile: str = Field(default="read_only", description="Permission profile used")

    # Execution tracking
    parameters_digest: str = Field(default="", description="Integrity hash of parameters")
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    status: ToolInvocationStatus = ToolInvocationStatus.REQUESTED

    # Results
    output_summary: str = Field(default="", description="Sanitized output summary")
    error_summary: str | None = Field(default=None, description="Sanitized error summary")
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple, description="Evidence items generated")

    # Metadata
    provenance: dict[str, Any] = Field(default_factory=dict, description="Invocation provenance")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    @field_validator("tool_id")
    @classmethod
    def tool_id_valid(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("tool_id must be non-empty")
        return v

    @field_validator("status")
    @classmethod
    def valid_status_transition(cls, v: ToolInvocationStatus, info) -> ToolInvocationStatus:
        # Basic validation - more complex transitions could be added
        if v not in [
            ToolInvocationStatus.REQUESTED,
            ToolInvocationStatus.VALIDATING,
            ToolInvocationStatus.POLICY_CHECK,
            ToolInvocationStatus.APPROVED,
            ToolInvocationStatus.EXECUTING,
            ToolInvocationStatus.COMPLETED,
            ToolInvocationStatus.DENIED,
            ToolInvocationStatus.FAILED,
            ToolInvocationStatus.TIMEOUT,
        ]:
            raise ValueError(f"Invalid status: {v}")
        return v

    def transition_to(self, new_status: ToolInvocationStatus) -> ToolInvocation:
        """Transition to a new status."""
        # Define valid state transitions
        valid_transitions: dict[ToolInvocationStatus, list[ToolInvocationStatus]] = {
            ToolInvocationStatus.REQUESTED: [
                ToolInvocationStatus.VALIDATING,
                ToolInvocationStatus.DENIED,
                ToolInvocationStatus.FAILED,
            ],
            ToolInvocationStatus.VALIDATING: [
                ToolInvocationStatus.POLICY_CHECK,
                ToolInvocationStatus.FAILED,
            ],
            ToolInvocationStatus.POLICY_CHECK: [
                ToolInvocationStatus.APPROVED,
                ToolInvocationStatus.DENIED,
                ToolInvocationStatus.FAILED,
            ],
            ToolInvocationStatus.APPROVED: [
                ToolInvocationStatus.EXECUTING,
                ToolInvocationStatus.DENIED,
            ],
            ToolInvocationStatus.EXECUTING: [
                ToolInvocationStatus.COMPLETED,
                ToolInvocationStatus.FAILED,
                ToolInvocationStatus.TIMEOUT,
            ],
            ToolInvocationStatus.COMPLETED: [],
            ToolInvocationStatus.DENIED: [],
            ToolInvocationStatus.FAILED: [],
            ToolInvocationStatus.TIMEOUT: [],
        }

        if new_status not in valid_transitions.get(self.status, []):
            raise ValueError(
                f"Invalid transition from {self.status.value} to {new_status.value}"
            )

        if new_status in [
            ToolInvocationStatus.COMPLETED,
            ToolInvocationStatus.DENIED,
            ToolInvocationStatus.FAILED,
            ToolInvocationStatus.TIMEOUT,
        ]:
            completed_at = datetime.now(timezone.utc).isoformat()
        else:
            completed_at = self.completed_at

        return ToolInvocation(
            **{
                **self.model_dump(),
                "status": new_status,
                "completed_at": completed_at,
            }
        )

    def update_output(self, output_summary: str, evidence_ids: tuple[str, ...] | None = None) -> ToolInvocation:
        """Update the output and evidence references of the invocation."""
        return ToolInvocation(
            **{
                **self.model_dump(),
                "output_summary": output_summary,
                "evidence_ids": evidence_ids or self.evidence_ids,
                "status": ToolInvocationStatus.COMPLETED,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    def update_error(self, error_summary: str) -> ToolInvocation:
        """Update the error information of the invocation."""
        return ToolInvocation(
            **{
                **self.model_dump(),
                "error_summary": error_summary,
                "status": ToolInvocationStatus.FAILED,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
        )


class ToolRegistry:
    """Central tool registry for EMO-Cyber-Agent.

    Manages tool discovery, resolution, and validation.
    Located in Core - no enforcement or execution capabilities.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        """Register a new tool specification."""
        if spec.tool_id in self._tools:
            raise ValueError(f"Tool already registered: {spec.tool_id}")

        self._tools[spec.tool_id] = spec

    def unregister(self, tool_id: str) -> None:
        """Unregister a tool."""
        if tool_id not in self._tools:
            raise ValueError(f"Tool not registered: {tool_id}")
        del self._tools[tool_id]

    def get(self, tool_id: str) -> ToolSpec:
        """Get a tool specification by ID."""
        if tool_id not in self._tools:
            raise ValueError(f"Tool not registered: {tool_id}")
        return self._tools[tool_id]

    def list(self) -> list[ToolSpec]:
        """List all registered tools."""
        return list(self._tools.values())

    def names(self) -> list[str]:
        """List all tool IDs."""
        return sorted(self._tools.keys())

    def validate(self, tool_id: str, **kwargs: Any) -> bool:
        """Validate a tool specification and parameters."""
        try:
            tool = self.get(tool_id)

            # Validate capabilities
            if not kwargs.get("capabilities"):
                return False

            for cap in kwargs["capabilities"]:
                if cap not in tool.capabilities_required:
                    return False

            # Validate target
            target = kwargs.get("target")
            if not target:
                return False
            if target not in tool.target_types:
                return False

            return True

        except Exception:
            return False

    def resolve(self, tool_id: str, **kwargs: Any) -> ToolSpec:
        """Resolve a tool specification with validation."""
        if not self.validate(tool_id, **kwargs):
            raise ValueError(f"Tool resolution failed for {tool_id}")

        return self.get(tool_id)