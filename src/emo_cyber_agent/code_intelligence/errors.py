"""Code intelligence errors — POST-RC-005.

Stable codes for every degraded or denied state. Incomplete analysis
is reported explicitly, never as "no vulnerability found".
"""

from __future__ import annotations

from enum import StrEnum


class CodeIntelligenceErrorCode(StrEnum):
    UNAVAILABLE = "CODE_INTELLIGENCE_UNAVAILABLE"
    UNSUPPORTED_LANGUAGE = "UNSUPPORTED_LANGUAGE"
    PARSE_FAILED = "PARSE_FAILED"
    SYMBOL_RESOLUTION_FAILED = "SYMBOL_RESOLUTION_FAILED"
    DATAFLOW_UNAVAILABLE = "DATAFLOW_UNAVAILABLE"
    QUERY_REJECTED = "QUERY_REJECTED"
    SNAPSHOT_INVALID = "SNAPSHOT_INVALID"
    GRAPH_LIMIT_REACHED = "GRAPH_LIMIT_REACHED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    STALE_SNAPSHOT = "STALE_SNAPSHOT"


class CodeIntelligenceError(Exception):
    def __init__(self, code: CodeIntelligenceErrorCode, message: str):
        super().__init__(f"{code.value}: {message}")
        self.code = code
