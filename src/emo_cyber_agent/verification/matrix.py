"""Verification matrix — POST-RC-012.

Connects a security hypothesis to the evidence it needs, the
candidate strategies that may test it, the adapter capabilities
they require, a bounded safety level, a target kind, an oracle,
and explicit refutation criteria. Selection through the matrix is
pure table lookup: deterministic, model-free, severity-free.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode
from emo_cyber_agent.verification.oracles import ORACLE_KINDS

HYPOTHESIS_KINDS: tuple[str, ...] = (
    "AUTHORIZATION",
    "OBJECT_AUTHORIZATION",
    "FUNCTION_AUTHORIZATION",
    "AUTHENTICATION",
    "INPUT_VALIDATION",
    "INJECTION",
    "DATA_FLOW",
    "SSRF",
    "PATH_TRAVERSAL",
    "SECRET_EXPOSURE",
    "OUTPUT_ENCODING",
    "CONFIGURATION",
    "DEPENDENCY",
    "MCP_SCOPE",
    "MCP_OUTPUT_ISOLATION",
    "AGENT_DELEGATION",
    "AGENT_CONTEXT",
    "REGRESSION",
    "STATE_CHANGE",
    "NETWORK_BEHAVIOR",
)

# Explicit synthetic test identities. Never provisioned automatically,
# never production credentials, never extracted from a target.
TEST_IDENTITIES: tuple[str, ...] = (
    "anonymous",
    "authenticated-user",
    "same-owner",
    "different-owner",
    "privileged-user",
    "administrator",
)

TEST_OPERATIONS: tuple[str, ...] = (
    "read",
    "create",
    "update",
    "delete",
    "admin-function",
    "state-change",
)

# Change predicates (POST-RC-008) → strategies that may test them.
CHANGE_STRATEGY_MAP: dict[str, tuple[str, ...]] = {
    "AUTH_BOUNDARY_CHANGED": ("authorization-matrix", "function-authorization"),
    "ROUTE_PERMISSION_CHANGED": ("function-authorization", "authorization-matrix"),
    "STATE_CHANGE_ADDED": ("state-change-authorization",),
    "NEW_STATE_CHANGE": ("state-change-authorization",),
    "DEPENDENCY_VERSION_CHANGED": ("dependency-resolution",),
    "NEW_EXTERNAL_INPUT": ("input-boundary", "sql-injection-safe"),
    "NEW_ROUTE": ("authorization-matrix", "input-boundary"),
    "REMOVED_CONTROL": ("configuration-property", "authorization-matrix"),
}

# Security skill packs (POST-RC-006) request strategies; packs never
# embed verification execution logic.
PACK_STRATEGY_MAP: dict[str, tuple[str, ...]] = {
    "injection-pack": ("sql-injection-safe", "command-injection-safe", "template-injection-safe", "interpreter-boundary", "deserialization-boundary"),
    "authz-pack": ("authorization-matrix", "function-authorization", "state-change-authorization"),
    "authentication-pack": ("authentication-boundary",),
    "agent-security-pack": ("mcp-scope", "mcp-tool-output-isolation", "agent-delegation-scope", "agent-context-isolation"),
    "config-pack": ("configuration-property", "dependency-resolution"),
    "data-exposure-pack": ("secret-exposure", "output-encoding", "path-traversal-boundary"),
    "ssrf-pack": ("ssrf-boundary",),
}

# Threat categories (POST-RC-009) → candidate strategies.
THREAT_STRATEGY_MAP: dict[str, tuple[str, ...]] = {
    "SPOOFING": ("authentication-boundary", "authorization-matrix"),
    "TAMPERING": ("static-property-check", "structural-consistency"),
    "REPUDIATION": ("configuration-property",),
    "INFORMATION_DISCLOSURE": ("secret-exposure", "output-encoding"),
    "DENIAL_OF_SERVICE": ("configuration-property",),
    "ELEVATION_OF_PRIVILEGE": ("authorization-matrix", "function-authorization"),
}

# Agent security categories (POST-RC-010) → candidate strategies.
AGENT_STRATEGY_MAP: dict[str, tuple[str, ...]] = {
    "PROMPT_INJECTION": ("agent-context-isolation",),
    "TOOL_POISONING": ("mcp-tool-output-isolation",),
    "SCOPE_CREEP": ("mcp-scope", "agent-delegation-scope"),
    "CREDENTIAL_EXPOSURE": ("secret-exposure", "agent-context-isolation"),
    "INSECURE_DELEGATION": ("agent-delegation-scope",),
}


class MatrixRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    hypothesis_kind: str
    required_evidence: tuple[str, ...] = ()
    candidate_strategies: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    safety_level: str = "PASSIVE"
    target_kind: str = "FILE"
    oracle_kind: str = "STRUCTURED_TOOL_RESULT"
    refutation_criteria: str = Field(..., min_length=1, max_length=500)

    @field_validator("hypothesis_kind")
    @classmethod
    def _hypothesis(cls, v: str) -> str:
        if v not in HYPOTHESIS_KINDS:
            raise ValueError(f"hypothesis kind not allowed: {v}")
        return v

    @field_validator("safety_level")
    @classmethod
    def _safety(cls, v: str) -> str:
        if v not in ("PASSIVE", "SAFE_ACTIVE", "RESTRICTED_ACTIVE"):
            raise ValueError(f"safety level not allowed: {v}")
        return v

    @field_validator("oracle_kind")
    @classmethod
    def _oracle(cls, v: str) -> str:
        if v not in ORACLE_KINDS:
            raise ValueError(f"oracle kind not allowed: {v}")
        return v


_DEFAULT_ROWS: tuple[dict[str, Any], ...] = (
    {"hypothesis_kind": "AUTHORIZATION", "required_evidence": ("route-record", "identity-boundary-record"), "candidate_strategies": ("authorization-matrix", "function-authorization"), "required_capabilities": ("AUTHZ_MATRIX", "SYNTHETIC_IDENTITY_TEST"), "safety_level": "SAFE_ACTIVE", "target_kind": "ROUTE", "oracle_kind": "AUTHZ_DECISION", "refutation_criteria": "a caller outside the declared authorization model observes an allowed decision"},
    {"hypothesis_kind": "OBJECT_AUTHORIZATION", "required_evidence": ("route-record", "object-ownership-record"), "candidate_strategies": ("authorization-matrix",), "required_capabilities": ("AUTHZ_MATRIX", "SYNTHETIC_IDENTITY_TEST"), "safety_level": "SAFE_ACTIVE", "target_kind": "API_OPERATION", "oracle_kind": "AUTHZ_DECISION", "refutation_criteria": "a caller addressing another owner's object observes an allowed decision"},
    {"hypothesis_kind": "FUNCTION_AUTHORIZATION", "required_evidence": ("route-record", "privilege-record"), "candidate_strategies": ("function-authorization",), "required_capabilities": ("AUTHZ_MATRIX", "SYNTHETIC_IDENTITY_TEST"), "safety_level": "SAFE_ACTIVE", "target_kind": "API_OPERATION", "oracle_kind": "AUTHZ_DECISION", "refutation_criteria": "an unauthenticated or regular caller reaches a privileged operation"},
    {"hypothesis_kind": "AUTHENTICATION", "required_evidence": ("identity-record", "session-record"), "candidate_strategies": ("authentication-boundary",), "required_capabilities": ("HTTP_REQUEST", "HTTP_ASSERTION"), "safety_level": "SAFE_ACTIVE", "target_kind": "ROUTE", "oracle_kind": "HTTP_STATUS", "refutation_criteria": "a missing or mismatched credential observes an accepted session"},
    {"hypothesis_kind": "INPUT_VALIDATION", "required_evidence": ("input-contract-record", "boundary-record"), "candidate_strategies": ("input-boundary",), "required_capabilities": ("HTTP_REQUEST", "HTTP_ASSERTION"), "safety_level": "SAFE_ACTIVE", "target_kind": "API_OPERATION", "oracle_kind": "HTTP_STATUS", "refutation_criteria": "an out-of-contract value crosses the validation boundary without a rejecting decision"},
    {"hypothesis_kind": "INJECTION", "required_evidence": ("dataflow-record", "boundary-record"), "candidate_strategies": ("sql-injection-safe", "command-injection-safe", "template-injection-safe"), "required_capabilities": ("HTTP_REQUEST", "HTTP_ASSERTION"), "safety_level": "SAFE_ACTIVE", "target_kind": "API_OPERATION", "oracle_kind": "STRUCTURED_TOOL_RESULT", "refutation_criteria": "an untrusted value reaches a sink without the declared boundary behaviour"},
    {"hypothesis_kind": "DATA_FLOW", "required_evidence": ("flow-record", "boundary-record"), "candidate_strategies": ("data-flow-confirmation", "structural-consistency"), "required_capabilities": ("GRAPH_ASSERTION", "FILE_ASSERTION"), "safety_level": "PASSIVE", "target_kind": "SYMBOL", "oracle_kind": "GRAPH_PROPERTY", "refutation_criteria": "a crossing of the declared boundary is observed in the flow graph"},
    {"hypothesis_kind": "SSRF", "required_evidence": ("url-contract-record", "network-control-record"), "candidate_strategies": ("ssrf-boundary",), "required_capabilities": ("HTTP_REQUEST", "HTTP_ASSERTION"), "safety_level": "SAFE_ACTIVE", "target_kind": "API_OPERATION", "oracle_kind": "HTTP_STATUS", "refutation_criteria": "a private or non-allowlisted destination is accepted by the URL validation property"},
    {"hypothesis_kind": "PATH_TRAVERSAL", "required_evidence": ("path-contract-record", "fixture-record"), "candidate_strategies": ("path-traversal-boundary",), "required_capabilities": ("FILE_ASSERTION", "STRUCTURED_TOOL_ASSERTION"), "safety_level": "SAFE_ACTIVE", "target_kind": "FILE", "oracle_kind": "FILE_STATE_PROPERTY", "refutation_criteria": "a normalized path escapes the fixture root"},
    {"hypothesis_kind": "SECRET_EXPOSURE", "required_evidence": ("credential-boundary-record", "output-record"), "candidate_strategies": ("secret-exposure",), "required_capabilities": ("FILE_ASSERTION", "STRUCTURED_TOOL_ASSERTION"), "safety_level": "PASSIVE", "target_kind": "FILE", "oracle_kind": "STRUCTURED_TOOL_RESULT", "refutation_criteria": "a canary value is observed outside the credential boundary"},
    {"hypothesis_kind": "OUTPUT_ENCODING", "required_evidence": ("output-contract-record", "encoding-record"), "candidate_strategies": ("output-encoding",), "required_capabilities": ("HTTP_REQUEST", "HTTP_ASSERTION"), "safety_level": "SAFE_ACTIVE", "target_kind": "ROUTE", "oracle_kind": "HTTP_BODY_PROPERTY", "refutation_criteria": "an untrusted value is emitted into the target context without encoding"},
    {"hypothesis_kind": "CONFIGURATION", "required_evidence": ("config-record", "setting-record"), "candidate_strategies": ("configuration-property",), "required_capabilities": ("CONFIG_ASSERTION", "FILE_ASSERTION"), "safety_level": "PASSIVE", "target_kind": "CONFIGURATION", "oracle_kind": "CONFIG_PROPERTY", "refutation_criteria": "the observed setting differs from the declared secure property"},
    {"hypothesis_kind": "DEPENDENCY", "required_evidence": ("package-record", "lockfile-record"), "candidate_strategies": ("dependency-resolution",), "required_capabilities": ("STRUCTURED_TOOL_ASSERTION", "FILE_ASSERTION"), "safety_level": "PASSIVE", "target_kind": "DEPENDENCY", "oracle_kind": "STRUCTURED_TOOL_RESULT", "refutation_criteria": "the resolved version differs from the declared lockfile identity"},
    {"hypothesis_kind": "MCP_SCOPE", "required_evidence": ("tool-scope-record", "server-record"), "candidate_strategies": ("mcp-scope",), "required_capabilities": ("MCP_ASSERTION", "STRUCTURED_TOOL_ASSERTION"), "safety_level": "PASSIVE", "target_kind": "MCP_TOOL", "oracle_kind": "STRUCTURED_TOOL_RESULT", "refutation_criteria": "effective tool scope exceeds the declared scope"},
    {"hypothesis_kind": "MCP_OUTPUT_ISOLATION", "required_evidence": ("tool-output-record", "authority-boundary-record"), "candidate_strategies": ("mcp-tool-output-isolation",), "required_capabilities": ("MCP_ASSERTION", "STRUCTURED_TOOL_ASSERTION"), "safety_level": "PASSIVE", "target_kind": "MCP_RESOURCE", "oracle_kind": "STRUCTURED_TOOL_RESULT", "refutation_criteria": "an untrusted tool result alters authorization or policy state"},
    {"hypothesis_kind": "AGENT_DELEGATION", "required_evidence": ("delegation-record", "scope-record"), "candidate_strategies": ("agent-delegation-scope",), "required_capabilities": ("AGENT_BOUNDARY_ASSERTION", "GRAPH_ASSERTION"), "safety_level": "PASSIVE", "target_kind": "AGENT_BOUNDARY", "oracle_kind": "GRAPH_PROPERTY", "refutation_criteria": "a child scope widens beyond the parent delegated subset"},
    {"hypothesis_kind": "AGENT_CONTEXT", "required_evidence": ("memory-record", "context-record"), "candidate_strategies": ("agent-context-isolation",), "required_capabilities": ("AGENT_BOUNDARY_ASSERTION", "GRAPH_ASSERTION"), "safety_level": "PASSIVE", "target_kind": "AGENT_BOUNDARY", "oracle_kind": "GRAPH_PROPERTY", "refutation_criteria": "untrusted context crosses into the authorization boundary"},
    {"hypothesis_kind": "REGRESSION", "required_evidence": ("historical-verification-record", "current-snapshot-record"), "candidate_strategies": ("regression-check",), "required_capabilities": ("STRUCTURED_TOOL_ASSERTION",), "safety_level": "PASSIVE", "target_kind": "SNAPSHOT", "oracle_kind": "STRUCTURED_TOOL_RESULT", "refutation_criteria": "the current observation differs from the verified baseline"},
    {"hypothesis_kind": "STATE_CHANGE", "required_evidence": ("state-transition-record", "authorization-record"), "candidate_strategies": ("state-change-authorization",), "required_capabilities": ("AUTHZ_MATRIX", "SYNTHETIC_IDENTITY_TEST"), "safety_level": "SAFE_ACTIVE", "target_kind": "API_OPERATION", "oracle_kind": "AUTHZ_DECISION", "refutation_criteria": "an unauthorized caller performs a state transition"},
    {"hypothesis_kind": "NETWORK_BEHAVIOR", "required_evidence": ("url-contract-record", "redirect-record"), "candidate_strategies": ("ssrf-boundary",), "required_capabilities": ("HTTP_REQUEST", "HTTP_ASSERTION"), "safety_level": "SAFE_ACTIVE", "target_kind": "ROUTE", "oracle_kind": "HTTP_STATUS", "refutation_criteria": "a redirect leaves the declared allowlist"},
)


class VerificationMatrix(BaseModel):
    model_config = ConfigDict(frozen=True)
    rows: tuple[MatrixRow, ...] = _DEFAULT_ROWS  # type: ignore[assignment]

    @classmethod
    def default(cls) -> VerificationMatrix:
        return cls(rows=tuple(MatrixRow(**row) for row in _DEFAULT_ROWS))

    def row(self, hypothesis_kind: str) -> MatrixRow:
        for row in self.rows:
            if row.hypothesis_kind == hypothesis_kind:
                return row
        raise StrategyError(StrategyErrorCode.SELECTION_FAILED, f"no matrix row for hypothesis: {hypothesis_kind}")

    def candidates(self, hypothesis_kind: str) -> tuple[str, ...]:
        return self.row(hypothesis_kind).candidate_strategies


class DeclaredAuthorization(BaseModel):
    """Declared/observed authorization model — facts, never inference.
    Endpoint naming is irrelevant: privilege comes from this model."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    grants: dict[str, tuple[str, ...]] = Field(default_factory=dict)

    @classmethod
    def from_model(cls, model: dict[str, Any]) -> DeclaredAuthorization:
        grants: dict[str, tuple[str, ...]] = {}
        for identity, operations in (model or {}).items():
            if identity not in TEST_IDENTITIES:
                raise StrategyError(StrategyErrorCode.SELECTION_FAILED, f"unknown test identity: {identity}")
            ops = tuple(operations)
            for operation in ops:
                if operation not in TEST_OPERATIONS:
                    raise StrategyError(StrategyErrorCode.SELECTION_FAILED, f"unknown test operation: {operation}")
            grants[identity] = ops
        return cls(grants=grants)


def expected_decision(declared: DeclaredAuthorization, *, identity: str, operation: str) -> str:
    if identity not in TEST_IDENTITIES or operation not in TEST_OPERATIONS:
        raise StrategyError(StrategyErrorCode.SELECTION_FAILED, "unknown identity or operation")
    return "ALLOW" if operation in declared.grants.get(identity, ()) else "DENY"


def authorization_cells(declared: DeclaredAuthorization) -> tuple[dict[str, str], ...]:
    """Full identity × operation expectation grid, deterministic order."""
    cells: list[dict[str, str]] = []
    for identity in TEST_IDENTITIES:
        for operation in TEST_OPERATIONS:
            cells.append({"identity": identity, "operation": operation, "expected": expected_decision(declared, identity=identity, operation=operation)})
    return tuple(cells)


def object_authorization_expectation(*, caller_owner: str, object_owner: str, caller_privileged: bool = False) -> str:
    """Object-level expectation from explicit ownership facts."""
    if caller_privileged:
        return "ALLOW"
    return "ALLOW" if caller_owner == object_owner and caller_owner else "DENY"


def row_oracle_subject(row: MatrixRow) -> str:
    """Stable observation key for a row's oracle kind."""
    return row.oracle_kind.lower()


def strategies_for_change(predicates: tuple[str, ...]) -> tuple[str, ...]:
    seen: list[str] = []
    for predicate in predicates:
        for strategy_id in CHANGE_STRATEGY_MAP.get(predicate, ()):
            if strategy_id not in seen:
                seen.append(strategy_id)
    return tuple(seen)


def strategies_for_pack(pack_id: str) -> tuple[str, ...]:
    return PACK_STRATEGY_MAP.get(pack_id, ())


def strategies_for_threat(category: str) -> tuple[str, ...]:
    return THREAT_STRATEGY_MAP.get(category, ())


def strategies_for_agent(category: str) -> tuple[str, ...]:
    return AGENT_STRATEGY_MAP.get(category, ())
