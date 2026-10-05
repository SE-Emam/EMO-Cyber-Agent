"""Advanced verification strategies — POST-RC-012.

A model-free strategy framework: closed vocabularies, frozen
contracts, deterministic planning, adapter-only execution, typed
oracles, and normalized evidence. This package decides nothing
about findings, severity, or lifecycle — Core owns all of that.
"""

from emo_cyber_agent.verification.adapter_contracts import (
    ADAPTER_CAPABILITIES,
    AdapterExecutionStatus,
    AdapterHealthState,
    OperationalResult,
    VerificationAdapter,
    VerificationAdapterCapabilities,
    VerificationAdapterContext,
    VerificationAdapterHealth,
    VerificationAdapterRequest,
    VerificationAdapterResponse,
)
from emo_cyber_agent.verification.adapter_provenance import (
    AdapterProvenance,
    build_adapter_provenance,
    provenance_of,
)
from emo_cyber_agent.verification.adapter_registry import VerificationAdapterRegistry
from emo_cyber_agent.verification.adapter_resolver import (
    AdapterBinding,
    AdapterBound,
    VerificationAdapterResolver,
)
from emo_cyber_agent.verification.adapters import (
    REFERENCE_ADAPTER_TYPES,
    SCENARIOS,
    build_reference_adapters,
)
from emo_cyber_agent.verification.budget import (
    BudgetUsage,
    ResourceBudget,
    effective_budget,
    retry_kind,
)
from emo_cyber_agent.verification.coverage import (
    CONCLUSION_CEILING,
    COVERAGE_STATES,
    CoverageAssessment,
    VerificationControls,
    assess_coverage,
)
from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode
from emo_cyber_agent.verification.evidence import (
    EvidenceCriteria,
    EvidenceOracle,
    VerificationEvidence,
    build_evidence,
    to_evidence_item,
)
from emo_cyber_agent.verification.matrix import (
    HYPOTHESIS_KINDS,
    DeclaredAuthorization,
    MatrixRow,
    VerificationMatrix,
    authorization_cells,
    expected_decision,
    row_oracle_subject,
    strategies_for_agent,
    strategies_for_change,
    strategies_for_pack,
    strategies_for_threat,
)
from emo_cyber_agent.verification.oracles import (
    CUSTOM_ASSERTIONS,
    ORACLE_KINDS,
    OracleOutcome,
    VerificationOracle,
    evaluate_oracle,
    oracle_from_spec,
    oracle_subject_of,
)
from emo_cyber_agent.verification.planner import (
    PLAN_STATUSES,
    StrategyVerificationResult,
    VerificationPlanner,
    VerificationStrategyPlan,
)
from emo_cyber_agent.verification.strategy import (
    CATEGORY_SAFETY_CEILING,
    INPUT_CONTRACTS,
    SAFETY_LEVELS,
    STRATEGY_CATEGORIES,
    TARGET_KINDS,
    StrategyCatalog,
    StrategyProvenance,
    StrategyTarget,
    VerificationStrategy,
    build_strategy,
    load_official_strategies,
    load_strategy,
    load_strategy_file,
)

__all__ = [
    "ADAPTER_CAPABILITIES",
    "CATEGORY_SAFETY_CEILING",
    "CONCLUSION_CEILING",
    "COVERAGE_STATES",
    "CUSTOM_ASSERTIONS",
    "HYPOTHESIS_KINDS",
    "INPUT_CONTRACTS",
    "ORACLE_KINDS",
    "PLAN_STATUSES",
    "REFERENCE_ADAPTER_TYPES",
    "SAFETY_LEVELS",
    "SCENARIOS",
    "STRATEGY_CATEGORIES",
    "TARGET_KINDS",
    "AdapterBinding",
    "AdapterBound",
    "AdapterExecutionStatus",
    "AdapterHealthState",
    "AdapterProvenance",
    "BudgetUsage",
    "CoverageAssessment",
    "DeclaredAuthorization",
    "EvidenceCriteria",
    "EvidenceOracle",
    "MatrixRow",
    "OperationalResult",
    "OracleOutcome",
    "ResourceBudget",
    "StrategyCatalog",
    "StrategyError",
    "StrategyErrorCode",
    "StrategyProvenance",
    "StrategyTarget",
    "StrategyVerificationResult",
    "VerificationAdapter",
    "VerificationAdapterCapabilities",
    "VerificationAdapterContext",
    "VerificationAdapterHealth",
    "VerificationAdapterRegistry",
    "VerificationAdapterRequest",
    "VerificationAdapterResolver",
    "VerificationAdapterResponse",
    "VerificationControls",
    "VerificationEvidence",
    "VerificationMatrix",
    "VerificationOracle",
    "VerificationPlanner",
    "VerificationStrategy",
    "VerificationStrategyPlan",
    "assess_coverage",
    "authorization_cells",
    "build_adapter_provenance",
    "build_evidence",
    "build_reference_adapters",
    "build_strategy",
    "effective_budget",
    "evaluate_oracle",
    "expected_decision",
    "load_official_strategies",
    "load_strategy",
    "load_strategy_file",
    "oracle_from_spec",
    "oracle_subject_of",
    "provenance_of",
    "retry_kind",
    "row_oracle_subject",
    "strategies_for_agent",
    "strategies_for_change",
    "strategies_for_pack",
    "strategies_for_threat",
    "to_evidence_item",
]
