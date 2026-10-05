"""Unit tests for Tool Registry (ECA-T004)

Tests the Tool Registry boundary, ToolSpec contracts, and ToolInvocation
lifecycle as implemented in Phase 4.

This test file focuses specifically on the Tool Registry and ToolInvocation
models and their integration with the core security components.
"""

import pytest
import uuid
from datetime import datetime

from emo_cyber_agent.domain.models import (
    AuditJob,
    Asset,
    AuditResult,
    EvidenceItem,
    Finding,
    FindingSeverity,
    FindingStatus,
    AuditStatus,
)
from emo_cyber_agent.core.contracts import PolicyEngine, SecurityAuditor
from emo_cyber_agent.core.service import DefaultPolicyEngine, FoundationSecurityAuditor
from emo_cyber_agent.core.tool_registry import (
    ToolRegistry,
    ToolSpec,
    ToolInvocation,
    ToolInvocationStatus,
)


def test_tool_spec_creation():
    """Test ToolSpec model creation and validation."""
    tool_spec = ToolSpec(
        tool_id="test-scanner",
        name="Test Scanner",
        version="1.0.0",
        description="Test tool for scanning",
        category="scanner",
        risk_level="low",
        capabilities_required=("read", "execute"),
        target_types=("repo",),
    )
    assert tool_spec.tool_id == "test-scanner"
    assert tool_spec.name == "Test Scanner"
    assert tool_spec.risk_level == "low"
    assert tool_spec.capabilities_required == ("read", "execute")
    assert tool_spec.target_types == ("repo",)


def test_tool_spec_missing_capabilities():
    """Test that ToolSpec requires at least one capability."""
    with pytest.raises(ValueError):
        ToolSpec(
            tool_id="test-tool",
            name="Test Tool",
            version="1.0.0",
            description="Test tool",
            category="other",
            risk_level="low",
            capabilities_required=(),
            target_types=("repo",),
        )


def test_tool_spec_missing_target_types():
    """Test that ToolSpec requires at least one target type."""
    with pytest.raises(ValueError):
        ToolSpec(
            tool_id="test-tool",
            name="Test Tool",
            version="1.0.0",
            description="Test tool",
            category="other",
            risk_level="low",
            capabilities_required=("read",),
            target_types=(),
        )


def test_tool_spec_risk_mismatch():
    """Test that ToolSpec validates risk level and capabilities."""
    # CRITICAL risk must support remediation
    with pytest.raises(ValueError):
        ToolSpec(
            tool_id="test-tool",
            name="Test Tool",
            version="1.0.0",
            description="Test tool",
            category="other",
            risk_level="critical",
            capabilities_required=("read",),
            target_types=("repo",),
            supports_remediation=False,
        )

    # HIGH risk must support verification
    with pytest.raises(ValueError):
        ToolSpec(
            tool_id="test-tool",
            name="Test Tool",
            version="1.0.0",
            description="Test tool",
            category="other",
            risk_level="high",
            capabilities_required=("read",),
            target_types=("repo",),
            supports_verification=False,
        )

    # LOW risk should not support remediation
    with pytest.raises(ValueError):
        ToolSpec(
            tool_id="test-tool",
            name="Test Tool",
            version="1.0.0",
            description="Test tool",
            category="other",
            risk_level="low",
            capabilities_required=("read",),
            target_types=("repo",),
            supports_remediation=True,
        )


def test_tool_registry_creation():
    """Test ToolRegistry basic functionality."""
    registry = ToolRegistry()
    assert len(registry.names()) == 0


def test_tool_registry_register_and_get():
    """Test ToolRegistry register and get methods."""
    registry = ToolRegistry()

    tool_spec = ToolSpec(
        tool_id="test-scanner",
        name="Test Scanner",
        version="1.0.0",
        description="Test tool",
        category="scanner",
        risk_level="low",
        capabilities_required=("read", "execute"),
        target_types=("repo",),
    )

    registry.register(tool_spec)
    assert len(registry.names()) == 1
    assert "test-scanner" in registry.names()

    retrieved_tool = registry.get("test-scanner")
    assert retrieved_tool.tool_id == "test-scanner"
    assert retrieved_tool.name == "Test Scanner"


def test_tool_registry_duplicate_registration():
    """Test that duplicate tool registration is rejected."""
    registry = ToolRegistry()

    tool_spec = ToolSpec(
        tool_id="test-scanner",
        name="Test Scanner",
        version="1.0.0",
        description="Test tool",
        category="scanner",
        risk_level="low",
        capabilities_required=("read", "execute"),
        target_types=("repo",),
    )

    registry.register(tool_spec)

    with pytest.raises(ValueError):
        registry.register(tool_spec)  # Same tool_id


def test_tool_registry_unregister():
    """Test ToolRegistry unregister method."""
    registry = ToolRegistry()

    tool_spec = ToolSpec(
        tool_id="test-scanner",
        name="Test Scanner",
        version="1.0.0",
        description="Test tool",
        category="scanner",
        risk_level="low",
        capabilities_required=("read", "execute"),
        target_types=("repo",),
    )

    registry.register(tool_spec)
    assert len(registry.names()) == 1

    registry.unregister("test-scanner")
    assert len(registry.names()) == 0

    with pytest.raises(ValueError):
        registry.get("test-scanner")


def test_tool_registry_get_nonexistent():
    """Test that getting a non-existent tool raises an error."""
    registry = ToolRegistry()

    with pytest.raises(ValueError):
        registry.get("non-existent")


def test_tool_registry_list():
    """Test ToolRegistry list method."""
    registry = ToolRegistry()

    tool_spec1 = ToolSpec(
        tool_id="tool-1",
        name="Tool 1",
        version="1.0.0",
        description="Test tool 1",
        category="scanner",
        risk_level="low",
        capabilities_required=("read",),
        target_types=("repo",),
    )

    tool_spec2 = ToolSpec(
        tool_id="tool-2",
        name="Tool 2",
        version="1.0.0",
        description="Test tool 2",
        category="secrets",
        risk_level="medium",
        capabilities_required=("scan",),
        target_types=("repo",),
    )

    registry.register(tool_spec1)
    registry.register(tool_spec2)

    tools = registry.list()
    assert len(tools) == 2
    assert any(t.tool_id == "tool-1" for t in tools)
    assert any(t.tool_id == "tool-2" for t in tools)


def test_tool_registry_validate():
    """Test ToolRegistry validation."""
    registry = ToolRegistry()

    tool_spec = ToolSpec(
        tool_id="test-scanner",
        name="Test Scanner",
        version="1.0.0",
        description="Test tool",
        category="scanner",
        risk_level="low",
        capabilities_required=("read", "execute"),
        target_types=("repo",),
    )

    registry.register(tool_spec)

    # Valid validation
    assert registry.validate("test-scanner", capabilities=("read",), target="repo") is True

    # Missing capabilities
    assert registry.validate("test-scanner", capabilities=("scan",), target="repo") is False

    # Missing target
    assert registry.validate("test-scanner", capabilities=("read",), target="invalid") is False


def test_tool_registry_resolve():
    """Test ToolRegistry resolve method."""
    registry = ToolRegistry()

    tool_spec = ToolSpec(
        tool_id="test-scanner",
        name="Test Scanner",
        version="1.0.0",
        description="Test tool",
        category="scanner",
        risk_level="low",
        capabilities_required=("read", "execute"),
        target_types=("repo",),
    )

    registry.register(tool_spec)

    # Valid resolve
    resolved = registry.resolve("test-scanner", capabilities=("read",), target="repo")
    assert resolved.tool_id == "test-scanner"

    # invalid resolve
    with pytest.raises(ValueError):
        registry.resolve("test-scanner", capabilities=("scan",), target="repo")


def test_toolinvocation_creation():
    """Test ToolInvocation model creation."""
    invocation = ToolInvocation(
        audit_id="audit-123",
        tool_id="test-scanner",
        target="repo1",
        requested_capabilities=("read", "execute"),
        profile="read_only",
    )
    assert invocation.invocation_id
    assert invocation.audit_id == "audit-123"
    assert invocation.tool_id == "test-scanner"
    assert invocation.target == "repo1"
    assert invocation.status == ToolInvocationStatus.REQUESTED


def test_toolinvocation_status_transitions():
    """Test ToolInvocation status transitions."""
    invocation = ToolInvocation(
        audit_id="audit-123",
        tool_id="test-scanner",
        target="repo1",
    )

    # Valid transitions
    validating = invocation.transition_to(ToolInvocationStatus.VALIDATING)
    assert validating.status == ToolInvocationStatus.VALIDATING

    policy_check = validating.transition_to(ToolInvocationStatus.POLICY_CHECK)
    assert policy_check.status == ToolInvocationStatus.POLICY_CHECK

    approved = policy_check.transition_to(ToolInvocationStatus.APPROVED)
    assert approved.status == ToolInvocationStatus.APPROVED

    executing = approved.transition_to(ToolInvocationStatus.EXECUTING)
    assert executing.status == ToolInvocationStatus.EXECUTING

    completed = executing.transition_to(ToolInvocationStatus.COMPLETED)
    assert completed.status == ToolInvocationStatus.COMPLETED
    assert completed.completed_at is not None


def test_toolinvocation_invalid_transition():
    """Test that invalid ToolInvocation status transitions are rejected."""
    invocation = ToolInvocation(
        audit_id="audit-123",
        tool_id="test-scanner",
        target="repo1",
    )

    validating = invocation.transition_to(ToolInvocationStatus.VALIDATING)

    with pytest.raises(ValueError, match="Invalid transition"):
        validating.transition_to(ToolInvocationStatus.COMPLETED)  # Skip POLICY_CHECK


def test_toolinvocation_update_output():
    """Test ToolInvocation output update."""
    invocation = ToolInvocation(
        audit_id="audit-123",
        tool_id="test-scanner",
        target="repo1",
    )

    validating = invocation.transition_to(ToolInvocationStatus.VALIDATING)
    policy_check = validating.transition_to(ToolInvocationStatus.POLICY_CHECK)
    approved = policy_check.transition_to(ToolInvocationStatus.APPROVED)
    executing = approved.transition_to(ToolInvocationStatus.EXECUTING)

    completed = executing.update_output(
        "Scan completed successfully",
        evidence_ids=("evidence-1", "evidence-2"),
    )

    assert completed.status == ToolInvocationStatus.COMPLETED
    assert completed.output_summary == "Scan completed successfully"
    assert completed.evidence_ids == ("evidence-1", "evidence-2")


def test_toolinvocation_update_error():
    """Test ToolInvocation error update."""
    invocation = ToolInvocation(
        audit_id="audit-123",
        tool_id="test-scanner",
        target="repo1",
    )

    validating = invocation.transition_to(ToolInvocationStatus.VALIDATING)
    policy_check = validating.transition_to(ToolInvocationStatus.POLICY_CHECK)
    approved = policy_check.transition_to(ToolInvocationStatus.APPROVED)

    failed = approved.update_error("Scan timeout")

    assert failed.status == ToolInvocationStatus.FAILED
    assert failed.error_summary == "Scan timeout"


def test_tool_spec_enum_values():
    """Test that all ToolCategory and RiskLevel enum values are accessible."""
    from emo_cyber_agent.core.tool_registry import ToolCategory, RiskLevel

    for category in ToolCategory:
        ToolSpec(
            tool_id="test-tool",
            name="Test Tool",
            version="1.0.0",
            description="Test tool",
            category=category.value,
            risk_level="low",
            capabilities_required=("read",),
            target_types=("repo",),
        )

    for risk in RiskLevel:
        if risk.value in ("high", "critical"):
            continue
        ToolSpec(
            tool_id="test-tool",
            name="Test Tool",
            version="1.0.0",
            description="Test tool",
            category="other",
            risk_level=risk.value,
            capabilities_required=("read",),
            target_types=("repo",),
        )


def test_tool_spec_validation():
    """Test ToolSpec validation with various inputs."""
    # Valid tool spec
    tool_spec = ToolSpec(
        tool_id="test-tool",
        name="Test Tool",
        version="1.0.0",
        description="Test tool",
        category="scanner",
        risk_level="low",
        capabilities_required=("read", "execute"),
        target_types=("repo", "database"),
    )

    assert tool_spec.tool_id == "test-tool"
    assert tool_spec.category == "scanner"
    assert tool_spec.risk_level == "low"
    assert tool_spec.capabilities_required == ("read", "execute")
    assert tool_spec.target_types == ("repo", "database")


def test_tool_spec_enum_categories():
    """Test all tool categories."""
    from emo_cyber_agent.core.tool_registry import ToolCategory

    categories = [c.value for c in ToolCategory]
    assert "scanner" in categories
    assert "secrets" in categories
    assert "dependency" in categories
    assert "repository" in categories
    assert "database" in categories
    assert "network" in categories
    assert "cloud" in categories
    assert "verification" in categories
    assert "other" in categories


def test_tool_spec_enum_risk_levels():
    """Test all risk levels."""
    from emo_cyber_agent.core.tool_registry import RiskLevel

    risk_levels = [r.value for r in RiskLevel]
    assert "low" in risk_levels
    assert "medium" in risk_levels
    assert "high" in risk_levels
    assert "critical" in risk_levels


def test_tool_spec_validation_comprehensive():
    """Test comprehensive ToolSpec validation."""
    # Test with all optional fields
    tool_spec = ToolSpec(
        tool_id="comprehensive-tool",
        name="Comprehensive Tool",
        version="2.0.0",
        description="A comprehensive tool with all fields",
        category="scanner",
        risk_level="medium",
        capabilities_required=("read", "scan", "analyze"),
        target_types=("repo", "database", "network"),
        supports_read_only=True,
        supports_verification=True,
        supports_remediation=False,
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        evidence_behavior="summarize",
        timeout_ms=60000,
        max_retries=3,
        concurrent_executions=5,
        provenance={"source": "internal"},
        tags=("security", "analysis"),
        documentation_url="https://example.com/docs",
        contact="security@example.com",
    )

    assert tool_spec.tool_id == "comprehensive-tool"
    assert tool_spec.version == "2.0.0"
    assert tool_spec.capabilities_required == ("read", "scan", "analyze")
    assert tool_spec.target_types == ("repo", "database", "network")
    assert tool_spec.supports_read_only is True
    assert tool_spec.supports_verification is True
    assert tool_spec.supports_remediation is False
    assert tool_spec.evidence_behavior == "summarize"
    assert tool_spec.timeout_ms == 60000
    assert tool_spec.max_retries == 3
    assert tool_spec.concurrent_executions == 5
    assert tool_spec.provenance == {"source": "internal"}
    assert tool_spec.tags == ("security", "analysis")


def test_toolinvocation_status_all():
    """Test all ToolInvocationStatus values."""
    from emo_cyber_agent.core.tool_registry import ToolInvocationStatus

    statuses = [s.value for s in ToolInvocationStatus]
    expected = [
        "requested",
        "validating",
        "policy_check",
        "approved",
        "executing",
        "completed",
        "denied",
        "failed",
        "timeout",
    ]

    for status in expected:
        assert status in statuses


def test_toolinvocation_transition_all():
    """Test all valid ToolInvocationStatus transitions."""
    from emo_cyber_agent.core.tool_registry import ToolInvocationStatus

    # Create a valid transition chain
    invocation = ToolInvocation(
        audit_id="audit-123",
        tool_id="test-tool",
        target="repo1",
    )

    # Valid chain
    current = invocation.transition_to(ToolInvocationStatus.VALIDATING)
    current = current.transition_to(ToolInvocationStatus.POLICY_CHECK)
    current = current.transition_to(ToolInvocationStatus.APPROVED)
    current = current.transition_to(ToolInvocationStatus.EXECUTING)
    current = current.transition_to(ToolInvocationStatus.COMPLETED)

    assert current.status == ToolInvocationStatus.COMPLETED


def test_tool_registry_names_ordering():
    """Test that tool registry returns names in sorted order."""
    registry = ToolRegistry()

    tools = [
        ToolSpec(
            tool_id="z-tool",
            name="Z Tool",
            version="1.0.0",
            description="Test tool Z",
            category="other",
            risk_level="low",
            capabilities_required=("read",),
            target_types=("repo",),
        ),
        ToolSpec(
            tool_id="a-tool",
            name="A Tool",
            version="1.0.0",
            description="Test tool A",
            category="other",
            risk_level="low",
            capabilities_required=("read",),
            target_types=("repo",),
        ),
        ToolSpec(
            tool_id="m-tool",
            name="M Tool",
            version="1.0.0",
            description="Test tool M",
            category="other",
            risk_level="low",
            capabilities_required=("read",),
            target_types=("repo",),
        ),
    ]

    for tool in tools:
        registry.register(tool)

    names = registry.names()
    assert names == ["a-tool", "m-tool", "z-tool"]


def test_tool_spec_to_tool_registry_integration():
    """Test integration between ToolSpec and ToolRegistry."""
    registry = ToolRegistry()

    # Create and register a tool spec
    tool_spec = ToolSpec(
        tool_id="integration-tool",
        name="Integration Tool",
        version="1.0.0",
        description="Test tool for integration",
        category="scanner",
        risk_level="low",
        capabilities_required=("read", "execute"),
        target_types=("repo",),
    )

    registry.register(tool_spec)

    # Resolve the tool
    resolved = registry.resolve("integration-tool", capabilities=("read",), target="repo")

    # Verify it's the same tool
    assert resolved.tool_id == tool_spec.tool_id
    assert resolved.name == tool_spec.name
    assert resolved.capabilities_required == tool_spec.capabilities_required


def test_toolinvocation_provenance_tracking():
    """Test ToolInvocation provenance tracking."""
    invocation = ToolInvocation(
        audit_id="audit-123",
        tool_id="test-tool",
        target="repo1",
        provenance={"source": "api", "version": "1.0.0"},
    )

    assert invocation.provenance == {"source": "api", "version": "1.0.0"}


def test_toolinvocation_metadata():
    """Test ToolInvocation metadata."""
    invocation = ToolInvocation(
        audit_id="audit-123",
        tool_id="test-tool",
        target="repo1",
        metadata={"user_id": "user123", "session_id": "session456"},
    )

    assert invocation.metadata == {"user_id": "user123", "session_id": "session456"}


def test_tool_spec_optional_fields():
    """Test that optional fields in ToolSpec have correct defaults."""
    tool_spec = ToolSpec(
        tool_id="test-tool",
        name="Test Tool",
        version="1.0.0",
        description="Test tool",
        category="scanner",
        risk_level="low",
        capabilities_required=("read",),
        target_types=("repo",),
    )

    # Check optional fields have correct defaults
    assert tool_spec.supports_read_only is True
    assert tool_spec.supports_verification is False
    assert tool_spec.supports_remediation is False
    assert tool_spec.input_schema == {}
    assert tool_spec.output_schema is None
    assert tool_spec.evidence_behavior == "summarize"
    assert tool_spec.timeout_ms is None
    assert tool_spec.max_retries == 0
    assert tool_spec.concurrent_executions == 1
    assert tool_spec.provenance == {}
    assert tool_spec.tags == ()
    assert tool_spec.documentation_url is None
    assert tool_spec.contact is None


def test_tool_registry_integration_with_core():
    """Test integration between ToolRegistry and Core components."""
    from emo_cyber_agent.core.service import FoundationSecurityAuditor

    # Create auditor with tool registry
    auditor = FoundationSecurityAuditor()

    # Test that auditor has access to tool registry
    assert auditor.tool_registry is not None
    assert isinstance(auditor.tool_registry, ToolRegistry)

    # Test that auditor can register tools
    tool_spec = ToolSpec(
        tool_id="integration-test",
        name="Integration Test Tool",
        version="1.0.0",
        description="Test tool for integration",
        category="scanner",
        risk_level="low",
        capabilities_required=("read",),
        target_types=("repo",),
    )

    auditor.tool_registry.register(tool_spec)
    assert auditor.tool_registry.get("integration-test").tool_id == "integration-test"