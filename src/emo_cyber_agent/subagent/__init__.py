"""Subagent delegation contracts — POST-T018.

Frozen, typed, server-authorized handoff contracts for delegating work to
subagent hosts. Envelopes carry delegation *requests*; authorization is
always server-issued (DelegationContext) and can never be minted from
model/host text. Lifecycle is coordination state, not a security engine.
"""

from emo_cyber_agent.subagent.capabilities import CapabilityEnvelope, EffectiveCapabilitySet
from emo_cyber_agent.subagent.envelope import (
    SUBAGENT_CONTRACT_VERSION,
    Budget,
    CancellationMetadata,
    DelegatedScope,
    DelegationContext,
    TaskEnvelope,
    assert_authorization_independent,
)
from emo_cyber_agent.subagent.handoff import (
    AuditHandoff,
    HealthSnapshot,
    ProvenanceLink,
    ResultEnvelope,
    ResultStatus,
)
from emo_cyber_agent.subagent.hosts import (
    SUBAGENT_API_VERSION,
    CompatibilityDecision,
    CompatibilityVerdict,
    HostProfile,
    check_compatibility,
)
from emo_cyber_agent.subagent.session import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    SubagentHealth,
    SubagentLifecycle,
    SubagentSession,
)
from emo_cyber_agent.subagent.trust import (
    ContextClassification,
    ContextTrust,
    DelegationSecurityDecision,
    HostErrorCode,
    HostIntegrationError,
    SecurityDecision,
    evaluate_context_trust,
    scan_secret_markers,
)

__all__ = [
    "SUBAGENT_API_VERSION",
    "SUBAGENT_CONTRACT_VERSION",
    "ALLOWED_TRANSITIONS",
    "TERMINAL_STATES",
    "AuditHandoff",
    "Budget",
    "CancellationMetadata",
    "CapabilityEnvelope",
    "CompatibilityDecision",
    "CompatibilityVerdict",
    "ContextClassification",
    "ContextTrust",
    "DelegatedScope",
    "DelegationContext",
    "DelegationSecurityDecision",
    "EffectiveCapabilitySet",
    "HealthSnapshot",
    "HostErrorCode",
    "HostIntegrationError",
    "HostProfile",
    "ProvenanceLink",
    "ResultEnvelope",
    "ResultStatus",
    "SecurityDecision",
    "SubagentHealth",
    "SubagentLifecycle",
    "SubagentSession",
    "TaskEnvelope",
    "assert_authorization_independent",
    "check_compatibility",
    "evaluate_context_trust",
    "scan_secret_markers",
]
