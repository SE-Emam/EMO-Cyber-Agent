"""Security knowledge & regression memory — POST-RC-011.

Scoped, provenance-preserving memory of security observations and
regression context. Memory is evidence-indexing, not truth: stored
records never become authority, current evidence, or Finding state.
Core holds no model weights and no provider-specific logic.
"""

from emo_cyber_agent.security_knowledge.comparator import KnowledgeComparator
from emo_cyber_agent.security_knowledge.errors import KnowledgeError, KnowledgeErrorCode
from emo_cyber_agent.security_knowledge.fingerprints import (
    asset_control_key,
    boundary_relation_key,
    package_property_key,
    regression_identity,
    regression_key_for,
    route_property_key,
    snapshot_identity,
    structural_identity,
    symbol_sink_key,
    tool_capability_key,
)
from emo_cyber_agent.security_knowledge.memory_policy import (
    check_category,
    check_content,
    retention_metadata,
)
from emo_cyber_agent.security_knowledge.provenance import (
    build_knowledge_provenance,
    extend_provenance,
    trace_chain,
)
from emo_cyber_agent.security_knowledge.queries import ALLOWED_KNOWLEDGE_QUERIES, KnowledgeQueryPort
from emo_cyber_agent.security_knowledge.records import build_knowledge_record, record_reference
from emo_cyber_agent.security_knowledge.regression import (
    compare_regression,
    evaluate_precedence,
    evaluate_staleness,
)
from emo_cyber_agent.security_knowledge.scope import (
    access_decision,
    bind_query_scope,
    check_record_scope,
)
from emo_cyber_agent.security_knowledge.service import (
    LAYER_CATEGORIES,
    LAYER_SOURCE_TYPES,
    SecurityKnowledgeService,
    check_forbidden_scope_tokens,
)
from emo_cyber_agent.security_knowledge.spec import (
    COMPARATOR_RESULTS,
    KNOWLEDGE_SCHEMA_VERSION,
    KNOWLEDGE_VERDICT_TOKENS,
    PERSISTABLE_CATEGORIES,
    PRECEDENCE_STATES,
    REGRESSION_STATES,
    SCOPE_KINDS,
    STALENESS_STATES,
    TRUST_LEVELS,
    VERIFICATION_RESULTS,
    EvidenceFingerprint,
    ExternalKnowledgeEnvelope,
    KnowledgeAccess,
    KnowledgeCoverage,
    KnowledgeProvenance,
    KnowledgeRecord,
    KnowledgeReference,
    KnowledgeRetention,
    KnowledgeScope,
    KnowledgeTemplateConfig,
    ObservationFingerprint,
    PackTrust,
    RegressionComparison,
    SecurityRegressionRecord,
    VerificationOutcomeRecord,
    assert_no_knowledge_verdicts,
)
from emo_cyber_agent.security_knowledge.store import InMemoryKnowledgeStore, SecurityKnowledgeStore
from emo_cyber_agent.security_knowledge.templates import (
    load_knowledge_template,
    load_official_knowledge_templates,
)

__all__ = [
    "ALLOWED_KNOWLEDGE_QUERIES",
    "COMPARATOR_RESULTS",
    "EXTERNAL_TRUST_LEVELS",
    "KNOWLEDGE_SCHEMA_VERSION",
    "KNOWLEDGE_VERDICT_TOKENS",
    "LAYER_CATEGORIES",
    "LAYER_SOURCE_TYPES",
    "PERSISTABLE_CATEGORIES",
    "PRECEDENCE_STATES",
    "REGRESSION_STATES",
    "SCOPE_KINDS",
    "STALENESS_STATES",
    "TRUST_LEVELS",
    "VERIFICATION_RESULTS",
    "EvidenceFingerprint",
    "ExternalKnowledgeEnvelope",
    "InMemoryKnowledgeStore",
    "KnowledgeAccess",
    "KnowledgeComparator",
    "KnowledgeCoverage",
    "KnowledgeError",
    "KnowledgeErrorCode",
    "KnowledgeProvenance",
    "KnowledgeQueryPort",
    "KnowledgeRecord",
    "KnowledgeReference",
    "KnowledgeRetention",
    "KnowledgeScope",
    "KnowledgeTemplateConfig",
    "ObservationFingerprint",
    "PackTrust",
    "RegressionComparison",
    "SecurityKnowledgeService",
    "SecurityKnowledgeStore",
    "SecurityRegressionRecord",
    "VerificationOutcomeRecord",
    "access_decision",
    "assert_no_knowledge_verdicts",
    "asset_control_key",
    "bind_query_scope",
    "boundary_relation_key",
    "build_knowledge_provenance",
    "build_knowledge_record",
    "check_category",
    "check_content",
    "check_forbidden_scope_tokens",
    "check_record_scope",
    "compare_regression",
    "evaluate_precedence",
    "evaluate_staleness",
    "extend_provenance",
    "load_knowledge_template",
    "load_official_knowledge_templates",
    "package_property_key",
    "record_reference",
    "regression_identity",
    "regression_key_for",
    "retention_metadata",
    "route_property_key",
    "snapshot_identity",
    "structural_identity",
    "symbol_sink_key",
    "tool_capability_key",
    "trace_chain",
]

EXTERNAL_TRUST_LEVELS: tuple[str, ...] = ("untrusted-external", "quarantined")
