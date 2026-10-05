"""Evaluation contracts and vocabularies — POST-RC-013.

The evaluation layer measures the *system* (Core + MCP/CLI/Python API
adapters), never a model provider. Nothing here imports a provider, opens
a socket, or reads host configuration: a run is a pure function of
(dataset, system under test, oracle set).

Vocabularies are closed. Unknown stages, tracks, splits, verdicts, gates,
matches, or ground-truth kinds are rejected at construction so a malformed
fixture can never silently pass through a metric.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.threat_modeling.spec import canonical_digest

__all__ = [
    "EVALUATION_VERSION",
    "EvaluationStage",
    "EvaluationTrack",
    "CaseSplit",
    "CaseVisibility",
    "EvaluationTaxonomy",
    "GroundTruthKind",
    "ComparisonMatch",
    "OracleVerdict",
    "GateName",
    "GateStatus",
    "RunStatus",
    "PIPELINE_STAGES",
    "PROTOCOL_STAGES",
    "ALL_STAGES",
    "SECURITY_GROUND_TRUTH_KINDS",
    "EvaluationEvent",
    "EvaluationObservation",
    "AuthoritySnapshot",
    "AuthorityDiff",
    "capture_authority",
    "diff_authority",
    "evaluation_digest",
    "digest_records",
    "utc_now",
]

EVALUATION_VERSION = "post-rc-013-v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------


class EvaluationStage(StrEnum):
    """Where an observation/judgment sits in the EMO workflow.

    The first block mirrors the mandatory workflow path (Core owns it);
    the second block adds evaluation protocol stages (parity, regression,
    authority, coverage) that are properties of an evaluation run rather
    than of a single audit.
    """

    INPUT_FACTS = "input_facts"
    NORMALIZED_FACTS = "normalized_facts"
    EVIDENCE = "evidence"
    CORRELATION = "correlation"
    HYPOTHESES = "hypotheses"
    VERIFICATION = "verification"
    FINDING_ELIGIBILITY = "finding_eligibility"
    REPORT = "report"
    AUTHORITY = "authority"
    PARITY = "parity"
    REGRESSION = "regression"
    COVERAGE = "coverage"
    ISOLATION = "isolation"
    DETECTION = "detection"
    SURFACE = "surface"


PIPELINE_STAGES: tuple[str, ...] = (
    EvaluationStage.INPUT_FACTS.value,
    EvaluationStage.NORMALIZED_FACTS.value,
    EvaluationStage.EVIDENCE.value,
    EvaluationStage.CORRELATION.value,
    EvaluationStage.HYPOTHESES.value,
    EvaluationStage.VERIFICATION.value,
    EvaluationStage.FINDING_ELIGIBILITY.value,
    EvaluationStage.REPORT.value,
)

PROTOCOL_STAGES: tuple[str, ...] = (
    EvaluationStage.AUTHORITY.value,
    EvaluationStage.PARITY.value,
    EvaluationStage.REGRESSION.value,
    EvaluationStage.COVERAGE.value,
    EvaluationStage.ISOLATION.value,
    EvaluationStage.DETECTION.value,
    EvaluationStage.SURFACE.value,
)

ALL_STAGES: tuple[str, ...] = PIPELINE_STAGES + PROTOCOL_STAGES


class EvaluationTrack(StrEnum):
    """Eight evaluation tracks (a run reports per track)."""

    DETECTION = "detection"
    REASONING = "reasoning"
    AUTHORITY = "authority"
    SAFETY = "safety"
    PARITY = "parity"
    REGRESSION = "regression"
    DETERMINISM = "determinism"
    PORTABILITY = "portability"


class CaseSplit(StrEnum):
    DEVELOPMENT = "development"
    VALIDATION = "validation"
    HOLDOUT = "holdout"


class CaseVisibility(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    BLIND = "blind"
    HOLDOUT = "holdout"
    ADVERSARIAL = "adversarial"
    REGRESSION = "regression"


class EvaluationTaxonomy(StrEnum):
    """16 evaluation taxonomy values (mirrors the Core finding taxonomy,
    drops ``other`` and adds the change/review category ``advisory_regression``)."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INJECTION = "injection"
    CRYPTOGRAPHY = "cryptography"
    SECRETS = "secrets"
    DEPENDENCY = "dependency"
    SUPPLY_CHAIN = "supply_chain"
    DATA_EXPOSURE = "data_exposure"
    CONFIGURATION = "configuration"
    API_SECURITY = "api_security"
    RLS = "rls"
    BUSINESS_LOGIC = "business_logic"
    INFRASTRUCTURE = "infrastructure"
    SESSION = "session"
    INPUT_VALIDATION = "input_validation"
    ADVISORY_REGRESSION = "advisory_regression"


class GroundTruthKind(StrEnum):
    EXPECTED_PRESENT = "expected_present"
    EXPECTED_ABSENT = "expected_absent"
    UNKNOWN = "unknown"
    INCONCLUSIVE = "inconclusive"
    STATE = "state"
    EVIDENCE = "evidence"
    RELATION = "relation"
    SCOPE_BEHAVIOR = "scope_behavior"
    EXPECTED_BLOCKED = "expected_blocked"
    EXPECTED_ISOLATED = "expected_isolated"
    EXPECTED_INERT = "expected_inert"
    EXPECTED_PRESERVED = "expected_preserved"
    AUTHORITY_INVARIANT = "authority_invariant"


class ComparisonMatch(StrEnum):
    EXACT = "exact"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    SUPERSET = "superset"
    SUBSET = "subset"
    SET_EQUALS = "set_equals"
    ABSENT = "absent"
    NONEMPTY = "nonempty"
    TRUE = "true"


class OracleVerdict(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class GateName(StrEnum):
    SECURITY_GATE = "security_gate"
    CORRECTNESS_GATE = "correctness_gate"
    REGRESSION_GATE = "regression_gate"


class GateStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_EVALUATED = "not_evaluated"
    NOT_APPLICABLE = "not_applicable"


class RunStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


# Kinds whose disagreement must fail the security gate (fail-closed).
SECURITY_GROUND_TRUTH_KINDS: frozenset[str] = frozenset(
    {
        GroundTruthKind.EXPECTED_BLOCKED.value,
        GroundTruthKind.EXPECTED_ISOLATED.value,
        GroundTruthKind.EXPECTED_INERT.value,
        GroundTruthKind.EXPECTED_PRESERVED.value,
        GroundTruthKind.AUTHORITY_INVARIANT.value,
    }
)

# Stages where a disagreement is treated as security-relevant by itself.
SECURITY_STAGES: frozenset[str] = frozenset(
    {
        EvaluationStage.AUTHORITY.value,
        EvaluationStage.ISOLATION.value,
        EvaluationStage.PARITY.value,
    }
)


# ---------------------------------------------------------------------------
# Digest helpers (deterministic identity, never wall-clock)
# ---------------------------------------------------------------------------


def evaluation_digest(payload: Mapping[str, Any]) -> str:
    return canonical_digest(dict(payload))


def digest_records(records: Iterable[BaseModel]) -> str:
    return canonical_digest({"records": [r.model_dump(mode="json") for r in records]})


# ---------------------------------------------------------------------------
# Events & observations
# ---------------------------------------------------------------------------


class EvaluationEvent(BaseModel):
    """Immutable run event. Only the id is volatile for identity purposes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:16]}")
    case_id: str = Field(..., min_length=1)
    stage: EvaluationStage
    kind: str = Field(..., min_length=1, max_length=64)
    sequence: int = Field(default=0, ge=0)
    payload: dict[str, Any] = Field(default_factory=dict)
    volatile_fields: tuple[str, ...] = ("event_id",)

    def identity_payload(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        for name in self.volatile_fields:
            data.pop(name, None)
        return data

    @property
    def identity_digest(self) -> str:
        return evaluation_digest(self.identity_payload())


class EvaluationObservation(BaseModel):
    """One system-produced fact bound to a workflow stage.

    ``volatile_fields`` names fields excluded from ``identity_digest`` so
    repeated runs of the same input stay byte-identical.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: str = Field(default_factory=lambda: f"obs-{uuid.uuid4().hex[:16]}")
    case_id: str = Field(..., min_length=1)
    stage: EvaluationStage
    kind: str = Field(default="observation", min_length=1, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
    volatile_fields: tuple[str, ...] = ("observation_id",)

    def identity_payload(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        for name in self.volatile_fields:
            data.pop(name, None)
        return data

    @property
    def identity_digest(self) -> str:
        return evaluation_digest(self.identity_payload())


# ---------------------------------------------------------------------------
# Authority snapshot (security authority model, before/after a case)
# ---------------------------------------------------------------------------


class AuthoritySnapshot(BaseModel):
    """The security authority state a system exposes.

    Only two things are authority: which findings exist with which status,
    and which policy grants are held. Policy *decisions* are operational
    records and never count as authority expansion.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    findings: dict[str, str] = Field(default_factory=dict)
    grants: dict[str, bool] = Field(default_factory=dict)
    captured_at: str = Field(default_factory=utc_now)
    volatile_fields: tuple[str, ...] = ("captured_at",)

    @field_validator("grants")
    @classmethod
    def _closed_grants(cls, v: dict[str, bool]) -> dict[str, bool]:
        allowed = {"read", "write", "network", "restricted"}
        unknown = set(v) - allowed
        if unknown:
            raise ValueError(f"unknown grant keys: {sorted(unknown)}")
        return v

    def identity_payload(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        for name in self.volatile_fields:
            data.pop(name, None)
        return data

    @property
    def identity_digest(self) -> str:
        return evaluation_digest(self.identity_payload())


class AuthorityDiff(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    state: str = Field(..., min_length=1)
    grant_expansions: tuple[str, ...] = ()
    finding_additions: tuple[str, ...] = ()
    finding_removals: tuple[str, ...] = ()
    status_changes: tuple[str, ...] = ()

    @property
    def preserved(self) -> bool:
        return self.state == "PRESERVED"


def capture_authority(
    *,
    findings: Mapping[str, str] | None = None,
    granted_read: bool = True,
    granted_write: bool = False,
    granted_network: bool = False,
    granted_restricted: bool = False,
) -> AuthoritySnapshot:
    return AuthoritySnapshot(
        findings=dict(findings or {}),
        grants={
            "read": bool(granted_read),
            "write": bool(granted_write),
            "network": bool(granted_network),
            "restricted": bool(granted_restricted),
        },
    )


def diff_authority(before: AuthoritySnapshot, after: AuthoritySnapshot) -> AuthorityDiff:
    """Pure structural comparison. A new grant or a changed finding status
    is authority movement; preserved state is the only accepted outcome for
    an ``EXPECTED_PRESERVED`` case."""
    expansions = tuple(
        sorted(
            key
            for key, value in after.grants.items()
            if value and not before.grants.get(key, False)
        )
    )
    additions = tuple(sorted(set(after.findings) - set(before.findings)))
    removals = tuple(sorted(set(before.findings) - set(after.findings)))
    changes = tuple(
        sorted(
            fid
            for fid in set(before.findings) & set(after.findings)
            if before.findings[fid] != after.findings[fid]
        )
    )
    if expansions:
        state = "GRANT_EXPANDED"
    elif additions or removals or changes:
        state = "FINDING_MUTATED"
    else:
        state = "PRESERVED"
    return AuthorityDiff(
        state=state,
        grant_expansions=expansions,
        finding_additions=additions,
        finding_removals=removals,
        status_changes=changes,
    )
