"""Change analysis errors — POST-RC-008."""

from __future__ import annotations

from enum import StrEnum


class ChangeErrorCode(StrEnum):
    INVALID = "CHANGE_INVALID"
    SNAPSHOT_MISMATCH = "CHANGE_SNAPSHOT_MISMATCH"
    STALE_SNAPSHOT = "CHANGE_STALE_SNAPSHOT"
    CROSS_AUDIT = "CHANGE_CROSS_AUDIT"
    CROSS_PROJECT = "CHANGE_CROSS_PROJECT"
    IDENTITY_TAMPERED = "CHANGE_IDENTITY_TAMPERED"
    DIFF_UNAVAILABLE = "CHANGE_DIFF_UNAVAILABLE"
    PROPAGATION_LIMIT = "CHANGE_PROPAGATION_LIMIT"
    PLAN_INVALID = "CHANGE_PLAN_INVALID"
    VERIFICATION_STALE = "CHANGE_VERIFICATION_STALE"
    WRITE_DENIED = "CHANGE_WRITE_DENIED"


class ChangeError(Exception):
    def __init__(self, code: ChangeErrorCode, message: str):
        super().__init__(f"{code.value}: {message}")
        self.code = code
