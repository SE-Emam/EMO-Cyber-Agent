"""Threat modeling errors — POST-RC-009."""

from __future__ import annotations

from enum import StrEnum


class ThreatModelErrorCode(StrEnum):
    INVALID = "THREAT_MODEL_INVALID"
    SNAPSHOT_MISMATCH = "THREAT_MODEL_SNAPSHOT_MISMATCH"
    STALE_SNAPSHOT = "THREAT_MODEL_STALE_SNAPSHOT"
    CROSS_AUDIT = "THREAT_MODEL_CROSS_AUDIT"
    CROSS_PROJECT = "THREAT_MODEL_CROSS_PROJECT"
    METHOD_UNKNOWN = "THREAT_MODEL_METHOD_UNKNOWN"
    QUERY_REJECTED = "THREAT_MODEL_QUERY_REJECTED"
    BUDGET_EXCEEDED = "THREAT_MODEL_BUDGET_EXCEEDED"
    VERIFICATION_STALE = "THREAT_MODEL_VERIFICATION_STALE"
    EVIDENCE_GAP = "THREAT_MODEL_EVIDENCE_GAP"


class ThreatModelError(Exception):
    def __init__(self, code: ThreatModelErrorCode, message: str):
        super().__init__(f"{code.value}: {message}")
        self.code = code
