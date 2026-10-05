"""Code Intelligence — POST-RC-005.

Answers "HOW IS THE PROGRAM STRUCTURED?" — never "IS THIS A
VULNERABILITY?". Chain: Code Intelligence → Evidence → Correlation →
Hypothesis → Verification → Finding.
"""

from emo_cyber_agent.code_intelligence.errors import CodeIntelligenceError, CodeIntelligenceErrorCode
from emo_cyber_agent.code_intelligence.graph import CodeGraph, GraphLimits
from emo_cyber_agent.code_intelligence.provider import PROVIDER_CAPABILITIES, CodeIntelligenceProvider
from emo_cyber_agent.code_intelligence.queries import ALLOWED_QUERY_TYPES, CodeGraphQueryPort
from emo_cyber_agent.code_intelligence.service import CodeIntelligenceService, get_code_intelligence_tool_specs
from emo_cyber_agent.code_intelligence.spec import (
    CODE_INTELLIGENCE_CONTRACT_VERSION,
    TAINT_TAXONOMY_VERSION,
    CodeProject,
    CodeSnapshot,
    ObservationKind,
    ResultQuality,
)

__all__ = [
    "ALLOWED_QUERY_TYPES",
    "CODE_INTELLIGENCE_CONTRACT_VERSION",
    "PROVIDER_CAPABILITIES",
    "TAINT_TAXONOMY_VERSION",
    "CodeGraph",
    "CodeGraphQueryPort",
    "CodeIntelligenceError",
    "CodeIntelligenceErrorCode",
    "CodeIntelligenceProvider",
    "CodeIntelligenceService",
    "CodeProject",
    "CodeSnapshot",
    "GraphLimits",
    "ObservationKind",
    "ResultQuality",
    "get_code_intelligence_tool_specs",
]
