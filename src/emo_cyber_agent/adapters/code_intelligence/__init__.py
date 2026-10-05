"""Code intelligence adapters — POST-RC-005.

Provider implementations live here, never in Core. mock: scripted
fixtures. reference: deterministic local analysis (stdlib ast +
patterns). Future: tree-sitter / joern / codeql adapters.
"""

from emo_cyber_agent.adapters.code_intelligence.mock import MockCodeIntelligenceProvider
from emo_cyber_agent.adapters.code_intelligence.reference import ReferenceLocalProvider

__all__ = ["MockCodeIntelligenceProvider", "ReferenceLocalProvider"]
