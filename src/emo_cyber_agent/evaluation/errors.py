"""Evaluation error surface — POST-RC-013.

Closed error codes for the evaluation layer. Every raised message passes
credential redaction: an evaluation run never leaks provider material,
target secrets, or host configuration into a report or a log line.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["EvaluationErrorCode", "EvaluationError"]


class EvaluationErrorCode(StrEnum):
    """Closed evaluation error vocabulary (EVALUATION_* prefix)."""

    INVALID_CASE = "EVALUATION_INVALID_CASE"
    INVALID_DATASET = "EVALUATION_INVALID_DATASET"
    DATASET_NOT_FOUND = "EVALUATION_DATASET_NOT_FOUND"
    DATASET_EMPTY = "EVALUATION_DATASET_EMPTY"
    CASE_NOT_FOUND = "EVALUATION_CASE_NOT_FOUND"
    BLIND_ACCESS_DENIED = "EVALUATION_BLIND_ACCESS_DENIED"
    BLIND_NOT_EXECUTED = "EVALUATION_BLIND_NOT_EXECUTED"
    ADAPTER_UNKNOWN = "EVALUATION_ADAPTER_UNKNOWN"
    ADAPTER_CAPABILITY_MISSING = "EVALUATION_ADAPTER_CAPABILITY_MISSING"
    ADAPTER_ERROR = "EVALUATION_ADAPTER_ERROR"
    ORACLE_REJECTED = "EVALUATION_ORACLE_REJECTED"
    METRIC_UNKNOWN = "EVALUATION_METRIC_UNKNOWN"
    GATE_UNKNOWN = "EVALUATION_GATE_UNKNOWN"
    MUTATION_REFUSED = "EVALUATION_MUTATION_REFUSED"
    MUTATION_INVALID = "EVALUATION_MUTATION_INVALID"
    CONTAMINATION_DETECTED = "EVALUATION_CONTAMINATION_DETECTED"
    AUTHORITY_DISAGREEMENT = "EVALUATION_AUTHORITY_DISAGREEMENT"
    NON_DETERMINISTIC = "EVALUATION_NON_DETERMINISTIC"
    REPORT_INVALID = "EVALUATION_REPORT_INVALID"
    RUN_NOT_FOUND = "EVALUATION_RUN_NOT_FOUND"
    PROTOCOL_ERROR = "EVALUATION_PROTOCOL_ERROR"
    INTERNAL = "EVALUATION_INTERNAL"


class EvaluationError(Exception):
    """Typed evaluation failure. The message is redacted at construction."""

    def __init__(self, code: EvaluationErrorCode, message: str) -> None:
        from emo_cyber_agent.core.repository import redact_credentials

        try:
            from emo_cyber_agent.core.supabase import redact_supabase_secrets

            clean = redact_supabase_secrets(redact_credentials(str(message)))
        except Exception:  # noqa: BLE001 - redaction must never raise
            clean = redact_credentials(str(message))
        super().__init__(f"{code.value}: {clean[:500]}")
        self.code = code
        self.message = clean[:500]
