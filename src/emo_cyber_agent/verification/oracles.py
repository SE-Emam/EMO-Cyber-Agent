"""Typed verification oracles — POST-RC-012.

An oracle is a bounded, declarative comparison between an observed
value and an expected value. No expressions, no eval/exec, no
user-supplied code: CUSTOM_ASSERTION is a closed vocabulary of
named checks implemented as a table.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode

ORACLE_KINDS: tuple[str, ...] = (
    "HTTP_STATUS",
    "HTTP_BODY_PROPERTY",
    "HEADER_PROPERTY",
    "DATABASE_STATE_PROPERTY",
    "FILE_STATE_PROPERTY",
    "CONFIG_PROPERTY",
    "GRAPH_PROPERTY",
    "AUTHZ_DECISION",
    "PROCESS_EXIT",
    "STRUCTURED_TOOL_RESULT",
    "CUSTOM_ASSERTION",
)

ORACLE_OPERATORS: tuple[str, ...] = (
    "EQUALS",
    "NOT_EQUALS",
    "CONTAINS",
    "NOT_CONTAINS",
    "EXISTS",
    "NOT_EXISTS",
    "IN_SET",
    "ABSENT_FROM_SET",
)

CUSTOM_ASSERTIONS: tuple[str, ...] = (
    "EXPECTED_DENY",
    "EXPECTED_ALLOW",
    "NO_UNSAFE_PROPAGATION",
    "ENCODING_APPLIED",
    "NO_SECRET_IN_OUTPUT",
    "SCOPE_NOT_WIDENED",
    "REDACTION_INTACT",
    "LOCKFILE_CONSISTENT",
    "DECLARED_EQ_EFFECTIVE",
    "NO_CROSS_BOUNDARY_FLOW",
)

# Declarative custom checks: name → predicate over the observed mapping.
# No dynamic code: this table is the entire execution surface.
_CUSTOM_TABLE: dict[str, str] = {
    "EXPECTED_DENY": "authz_decision == deny",
    "EXPECTED_ALLOW": "authz_decision == allow",
    "NO_UNSAFE_PROPAGATION": "unsafe_propagation == false",
    "ENCODING_APPLIED": "encoding_applied == true",
    "NO_SECRET_IN_OUTPUT": "secret_emitted == false",
    "SCOPE_NOT_WIDENED": "scope_widened == false",
    "REDACTION_INTACT": "redaction_intact == true",
    "LOCKFILE_CONSISTENT": "lockfile_consistent == true",
    "DECLARED_EQ_EFFECTIVE": "declared_equals_effective == true",
    "NO_CROSS_BOUNDARY_FLOW": "cross_boundary_flow == false",
}

_CODE_TOKENS = ("__import__", "eval(", "exec(", "compile(", "lambda", "os.", "subprocess", "globals(", "locals(", "getattr(", "0x")


class OracleOutcome(StrEnum):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationOracle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: str
    subject: str = Field(..., min_length=1, max_length=200)
    operator: str
    expected: str = Field(default="", max_length=500)
    assertion: str = Field(default="", max_length=80)

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in ORACLE_KINDS:
            raise ValueError(f"oracle kind not allowed: {v}")
        return v

    @field_validator("operator")
    @classmethod
    def _op(cls, v: str) -> str:
        if v not in ORACLE_OPERATORS:
            raise ValueError(f"oracle operator not allowed: {v}")
        return v

    @field_validator("subject", "expected", "assertion")
    @classmethod
    def _no_code(cls, v: str) -> str:
        lowered = (v or "").lower()
        for token in _CODE_TOKENS:
            if token in lowered:
                raise ValueError(f"code-like oracle input denied: {token}")
        if "\x00" in (v or ""):
            raise ValueError("null byte denied")
        return v

    @field_validator("assertion")
    @classmethod
    def _assertion(cls, v: str) -> str:
        if v and v not in CUSTOM_ASSERTIONS:
            raise ValueError(f"unknown custom assertion: {v}")
        return v


def evaluate_oracle(oracle: VerificationOracle, observed: dict[str, Any]) -> tuple[OracleOutcome, str]:
    """Deterministic comparison. Returns (outcome, reason_code).
    Missing observations are INCONCLUSIVE, never REFUTED."""
    value = observed.get(oracle.subject)
    if oracle.kind == "CUSTOM_ASSERTION":
        return _evaluate_custom(oracle, observed)
    if value is None:
        return OracleOutcome.INCONCLUSIVE, "observation-missing"
    if oracle.operator in ("EXISTS", "NOT_EXISTS"):
        present = value not in ("", None)
        expected_present = oracle.operator == "EXISTS"
        return (OracleOutcome.SUPPORTED, "exists-as-expected") if present == expected_present else (OracleOutcome.REFUTED, "existence-mismatch")
    left = _norm(value)
    right = _norm(oracle.expected)
    if oracle.operator == "EQUALS":
        return (OracleOutcome.SUPPORTED, "equal") if left == right else (OracleOutcome.REFUTED, "not-equal")
    if oracle.operator == "NOT_EQUALS":
        return (OracleOutcome.SUPPORTED, "not-equal") if left != right else (OracleOutcome.REFUTED, "equal")
    if oracle.operator == "CONTAINS":
        return (OracleOutcome.SUPPORTED, "contains") if right in left else (OracleOutcome.REFUTED, "missing")
    if oracle.operator == "NOT_CONTAINS":
        return (OracleOutcome.SUPPORTED, "absent") if right not in left else (OracleOutcome.REFUTED, "present")
    if oracle.operator == "IN_SET":
        allowed = {part.strip() for part in right.split(",") if part.strip()}
        return (OracleOutcome.SUPPORTED, "in-set") if left in allowed else (OracleOutcome.REFUTED, "out-of-set")
    allowed = {part.strip() for part in right.split(",") if part.strip()}
    return (OracleOutcome.SUPPORTED, "absent-from-set") if left not in allowed else (OracleOutcome.REFUTED, "in-set")


def _evaluate_custom(oracle: VerificationOracle, observed: dict[str, Any]) -> tuple[OracleOutcome, str]:
    expression = _CUSTOM_TABLE[oracle.assertion]
    key, _, expected = expression.partition(" == ")
    value = observed.get(key)
    if value is None:
        return OracleOutcome.INCONCLUSIVE, "observation-missing"
    expected_norm = expected.strip()
    actual = str(value).strip().lower()
    if expected_norm in ("true", "false"):
        matched = actual == expected_norm
    else:
        matched = actual == expected_norm
    return (OracleOutcome.SUPPORTED, "custom-assertion-held") if matched else (OracleOutcome.REFUTED, "custom-assertion-broken")


def _norm(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ",".join(_norm(v) for v in value)
    return str(value).strip()


def custom_expression(assertion: str) -> tuple[str, str]:
    """Declarative custom assertion → (observed key, expected value)."""
    expression = _CUSTOM_TABLE.get(assertion, "")
    if not expression:
        raise StrategyError(StrategyErrorCode.ORACLE_REJECTED, f"unknown custom assertion: {assertion}")
    key, _, expected = expression.partition(" == ")
    return key.strip(), expected.strip()


def oracle_subject_of(oracle: VerificationOracle) -> str:
    """The observed key an oracle reads. CUSTOM assertions read their
    own table key so a provider cannot rename the observation."""
    if oracle.kind == "CUSTOM_ASSERTION":
        return custom_expression(oracle.assertion)[0]
    return oracle.subject


def oracle_from_spec(spec: dict[str, Any]) -> VerificationOracle:
    try:
        return VerificationOracle(**{k: spec[k] for k in ("kind", "subject", "operator") if k in spec}, expected=str(spec.get("expected", "")), assertion=str(spec.get("assertion", "")))
    except (ValueError, TypeError, KeyError) as e:
        raise StrategyError(StrategyErrorCode.ORACLE_REJECTED, str(e)) from e
