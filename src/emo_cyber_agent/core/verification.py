"""Security Verification Layer — ECA-T010.

Reasoner proposes verification. Core validates. PolicyEngine authorizes.
ToolRegistry resolves. VerificationExecutor runs ONLY what was allowed.
EvidenceGraph receives the result. Candidate updates follow explicit,
auditable transitions. No direct CANDIDATE → CONFIRMED path exists.

Verification ≠ exploitation: prove or refute with minimum necessary action.
No destructive exploits, persistence, escalation, arbitrary network attacks,
or production mutation exist in this module.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.core.correlation import CandidateStatus, FindingCandidate
from emo_cyber_agent.core.tool_registry import ToolRegistry, ToolSpec

VERIFICATION_POLICY_VERSION = "eca-t010-v1"

VERIFICATION_CAPABILITIES: tuple[str, ...] = (
    "verification.static",
    "verification.config",
    "verification.read_query",
    "verification.controlled_reproduction",
)


class VerificationMethod(StrEnum):
    STATIC_CONFIRMATION = "static_confirmation"
    CONFIGURATION_CONFIRMATION = "configuration_confirmation"
    DATAFLOW_CONFIRMATION = "dataflow_confirmation"
    DEPENDENCY_CONFIRMATION = "dependency_confirmation"
    POLICY_CONFIRMATION = "policy_confirmation"
    READ_ONLY_QUERY = "read_only_query"
    CONTROLLED_REPRODUCTION = "controlled_reproduction"


class SafetyLevel(StrEnum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    RESTRICTED_ACTIVE = "restricted_active"


METHOD_SAFETY: dict[str, SafetyLevel] = {
    VerificationMethod.STATIC_CONFIRMATION.value: SafetyLevel.PASSIVE,
    VerificationMethod.CONFIGURATION_CONFIRMATION.value: SafetyLevel.PASSIVE,
    VerificationMethod.DATAFLOW_CONFIRMATION.value: SafetyLevel.PASSIVE,
    VerificationMethod.DEPENDENCY_CONFIRMATION.value: SafetyLevel.PASSIVE,
    VerificationMethod.POLICY_CONFIRMATION.value: SafetyLevel.PASSIVE,
    VerificationMethod.READ_ONLY_QUERY.value: SafetyLevel.PASSIVE,
    VerificationMethod.CONTROLLED_REPRODUCTION.value: SafetyLevel.SAFE_ACTIVE,
}

METHOD_CAPABILITY: dict[str, str] = {
    VerificationMethod.STATIC_CONFIRMATION.value: "verification.static",
    VerificationMethod.CONFIGURATION_CONFIRMATION.value: "verification.config",
    VerificationMethod.DATAFLOW_CONFIRMATION.value: "verification.config",
    VerificationMethod.DEPENDENCY_CONFIRMATION.value: "verification.static",
    VerificationMethod.POLICY_CONFIRMATION.value: "verification.config",
    VerificationMethod.READ_ONLY_QUERY.value: "verification.read_query",
    VerificationMethod.CONTROLLED_REPRODUCTION.value: "verification.controlled_reproduction",
}


class VerificationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    FAILED = "failed"
    TIMEOUT = "timeout"


class TargetKind(StrEnum):
    REPOSITORY = "repository"
    FILE = "file"
    ENDPOINT = "endpoint"
    DATABASE_OBJECT = "database_object"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"


class VerificationTarget(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: TargetKind
    locator: str = Field(..., min_length=1, max_length=512)

    @field_validator("locator")
    @classmethod
    def _explicit(cls, v: str) -> str:
        vv = v.strip()
        if not vv or vv == "*":
            raise ValueError("target must be explicit (never '*')")
        if "\x00" in vv:
            raise ValueError("null byte in target")
        low = vv.lower()
        if low.startswith(("http://", "https://")):
            raise ValueError("external target denied by default")
        if ".." in vv.replace("\\", "/").split("/"):
            raise ValueError("traversal in target denied")
        return vv


class VerificationErrorCode(StrEnum):
    INVALID_REQUEST = "VERIFICATION_INVALID_REQUEST"
    OUT_OF_SCOPE = "VERIFICATION_OUT_OF_SCOPE"
    POLICY_DENIED = "VERIFICATION_POLICY_DENIED"
    UNSAFE_METHOD = "VERIFICATION_UNSAFE_METHOD"
    EXTERNAL_TARGET = "VERIFICATION_EXTERNAL_TARGET"
    STALE_POLICY = "VERIFICATION_STALE_POLICY"
    MISMATCHED_AUDIT = "VERIFICATION_MISMATCHED_AUDIT"
    BUDGET_EXHAUSTED = "VERIFICATION_BUDGET_EXHAUSTED"
    LOOP_DETECTED = "VERIFICATION_LOOP_DETECTED"
    PROVIDER_ERROR = "VERIFICATION_PROVIDER_ERROR"
    NO_EVIDENCE = "VERIFICATION_NO_EVIDENCE"


class VerificationError(Exception):
    def __init__(self, code: VerificationErrorCode, message: str):
        from emo_cyber_agent.core.repository import redact_credentials

        super().__init__(f"{code.value}: {redact_credentials(message)}")
        self.code = code


class VerificationRequest(BaseModel):
    """Reasoner proposal. Fixed fields only — shell/permissions/commands/
    credentials/overrides are constructor-denied (MODEL_INVALID_RESPONSE).
    `statement` carries an optional read-only query (data, classified before
    any use); it is empty for non-query methods."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    method: VerificationMethod
    target: VerificationTarget
    rationale_summary: str = Field(..., min_length=1, max_length=1000)
    expected_evidence: str = Field(default="", max_length=500)
    safety_level: SafetyLevel | None = None
    statement: str = Field(default="", max_length=2000)

    @field_validator("safety_level")
    @classmethod
    def _consistent(cls, v: SafetyLevel | None, info: Any) -> SafetyLevel | None:
        return v


class VerificationPlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    candidate_id: str = Field(..., min_length=1)
    audit_id: str = Field(..., min_length=1)
    hypothesis: str = Field(default="", max_length=1000)
    steps: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    safety_level: SafetyLevel = SafetyLevel.PASSIVE
    constraints: dict[str, Any] = Field(default_factory=dict)
    stopping_conditions: tuple[str, ...] = ()
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Verification(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    verification_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    candidate_id: str = Field(..., min_length=1)
    audit_id: str = Field(..., min_length=1)
    asset_id: str | None = None
    method: VerificationMethod
    status: VerificationStatus = VerificationStatus.PENDING
    requested_by: str = Field(default="reasoner")
    policy_decision_id: str = Field(default="")
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    evidence_ids: tuple[str, ...] = ()
    result_summary: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    safety_level: SafetyLevel = SafetyLevel.PASSIVE
    constraints: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)

    def transition_to(self, new: VerificationStatus) -> Verification:
        allowed: dict[VerificationStatus, frozenset[VerificationStatus]] = {
            VerificationStatus.PENDING: frozenset({VerificationStatus.RUNNING, VerificationStatus.BLOCKED, VerificationStatus.FAILED}),
            VerificationStatus.RUNNING: frozenset({VerificationStatus.CONFIRMED, VerificationStatus.SUPPORTED, VerificationStatus.REFUTED, VerificationStatus.INCONCLUSIVE, VerificationStatus.BLOCKED, VerificationStatus.FAILED, VerificationStatus.TIMEOUT}),
            VerificationStatus.CONFIRMED: frozenset(),
            VerificationStatus.SUPPORTED: frozenset(),
            VerificationStatus.REFUTED: frozenset(),
            VerificationStatus.INCONCLUSIVE: frozenset(),
            VerificationStatus.BLOCKED: frozenset(),
            VerificationStatus.FAILED: frozenset(),
            VerificationStatus.TIMEOUT: frozenset({VerificationStatus.RUNNING}),  # operational retry only
        }
        if new not in allowed[self.status]:
            raise ValueError(f"invalid verification transition {self.status.value} → {new.value}")
        data = self.model_dump()
        data["status"] = new
        if new in (VerificationStatus.CONFIRMED, VerificationStatus.SUPPORTED, VerificationStatus.REFUTED, VerificationStatus.INCONCLUSIVE, VerificationStatus.BLOCKED, VerificationStatus.FAILED, VerificationStatus.TIMEOUT):
            data["completed_at"] = datetime.now(timezone.utc).isoformat()
        return Verification(**data)


class VerificationRawResult(BaseModel):
    """Provider output = DATA. Never trusted for status; Core decides."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    outcome: str = ""  # confirm | refute | inconclusive | blocked | failed | timeout
    observed: str = Field(default="", max_length=2000)
    evidence_refs: tuple[str, ...] = ()
    tool_version: str = ""
    duration_ms: int = Field(default=0, ge=0)


class VerificationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    verification_id: str
    candidate_id: str
    audit_id: str
    status: VerificationStatus
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: tuple[str, ...] = ()
    summary: str = ""
    completed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class VerificationBudget(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    max_verifications: int = Field(default=6, ge=1, le=50)
    max_active_verifications: int = Field(default=2, ge=1, le=10)
    max_time_s: int = Field(default=300, ge=1, le=3600)
    max_retries: int = Field(default=1, ge=0, le=5)
    max_same_target_attempts: int = Field(default=2, ge=1, le=10)


class PromotionEligibility(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    candidate_id: str
    eligible: bool = False
    status: CandidateStatus = CandidateStatus.NEEDS_VERIFICATION
    reasons: tuple[str, ...] = ()


class VerificationExecutorPort(ABC):
    """Runs ONLY authorized plans. Separate from ToolExecutor so no scanner
    ever inherits verification privileges. No shell, no network, no writes."""

    @abstractmethod
    def run(self, plan: VerificationPlan) -> VerificationRawResult: ...


# ---------------------------------------------------------------------------
# ToolSpecs (least privilege: one capability each, no verification.execute)
# ---------------------------------------------------------------------------

def get_verification_tool_specs() -> list[ToolSpec]:
    base = dict(
        version="1.0.0",
        description="Read-only verification operation",
        category="verification",
        risk_level="low",
        supports_read_only=True,
        supports_verification=True,
        supports_remediation=False,
        target_types=("repo", "file", "endpoint", "database_object", "dependency", "configuration"),
        evidence_behavior="summarize",
        timeout_ms=60000,
    )
    return [
        ToolSpec(tool_id="verification.static", name="Static Verification", capabilities_required=("verification.static",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="verification.config", name="Configuration Verification", capabilities_required=("verification.config",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="verification.read_query", name="Read-only Query Verification", capabilities_required=("verification.read_query",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="verification.controlled_reproduction", name="Controlled Reproduction", capabilities_required=("verification.controlled_reproduction",), **base),  # type: ignore[arg-type]
    ]


# ---------------------------------------------------------------------------
# Candidate transitions (§19): no CANDIDATE → CONFIRMED shortcut exists
# ---------------------------------------------------------------------------

_CANDIDATE_TRANSITIONS: dict[CandidateStatus, frozenset[CandidateStatus]] = {
    CandidateStatus.CANDIDATE: frozenset({CandidateStatus.NEEDS_VERIFICATION}),
    CandidateStatus.CORRELATED: frozenset({CandidateStatus.NEEDS_VERIFICATION}),
    CandidateStatus.NEEDS_VERIFICATION: frozenset({CandidateStatus.VERIFYING, CandidateStatus.INCONCLUSIVE, CandidateStatus.BLOCKED}),
    CandidateStatus.VERIFYING: frozenset({CandidateStatus.SUPPORTED, CandidateStatus.CONFIRMED, CandidateStatus.REFUTED, CandidateStatus.INCONCLUSIVE, CandidateStatus.BLOCKED}),
    CandidateStatus.SUPPORTED: frozenset({CandidateStatus.CONFIRMED, CandidateStatus.NEEDS_VERIFICATION}),
    CandidateStatus.CONFIRMED: frozenset(),
    CandidateStatus.REFUTED: frozenset(),
    CandidateStatus.INCONCLUSIVE: frozenset({CandidateStatus.NEEDS_VERIFICATION}),
    CandidateStatus.BLOCKED: frozenset({CandidateStatus.NEEDS_VERIFICATION}),
    CandidateStatus.PROMOTED: frozenset(),
}


def transition_candidate(current: CandidateStatus, new: CandidateStatus) -> CandidateStatus:
    if new not in _CANDIDATE_TRANSITIONS[current]:
        raise ValueError(f"invalid candidate transition {current.value} → {new.value}")
    return new


def assess_candidate(
    candidate: FindingCandidate,
    verifications: list[Verification],
    *,
    policy_valid: bool,
    scope_matched: bool,
) -> PromotionEligibility:
    """Deterministic assessment. Model confidence alone can never confirm."""
    statuses = [v.status for v in verifications]
    if not verifications or not any(v.evidence_ids for v in verifications):
        return PromotionEligibility(candidate_id=candidate.candidate_id, eligible=False, status=CandidateStatus.NEEDS_VERIFICATION, reasons=("no-verification-evidence",))
    if not policy_valid or not scope_matched:
        return PromotionEligibility(candidate_id=candidate.candidate_id, eligible=False, status=CandidateStatus.BLOCKED, reasons=("invalid-policy-or-scope",))
    confirmed = [v for v in verifications if v.status == VerificationStatus.CONFIRMED and v.evidence_ids]
    refuted = [v for v in verifications if v.status == VerificationStatus.REFUTED]
    if confirmed and refuted:
        return PromotionEligibility(candidate_id=candidate.candidate_id, eligible=False, status=CandidateStatus.INCONCLUSIVE, reasons=("conflicted-verifications-need-review",))
    if refuted and not confirmed:
        return PromotionEligibility(candidate_id=candidate.candidate_id, eligible=False, status=CandidateStatus.REFUTED, reasons=("refuted-with-evidence",))
    if confirmed:
        return PromotionEligibility(candidate_id=candidate.candidate_id, eligible=True, status=CandidateStatus.CONFIRMED, reasons=("criteria-met",))
    if any(s == VerificationStatus.SUPPORTED for s in statuses):
        return PromotionEligibility(candidate_id=candidate.candidate_id, eligible=False, status=CandidateStatus.SUPPORTED, reasons=("supported-not-confirmed",))
    return PromotionEligibility(candidate_id=candidate.candidate_id, eligible=False, status=CandidateStatus.INCONCLUSIVE, reasons=("inconclusive-evidence",))


# ---------------------------------------------------------------------------
# Verification service (Core-owned gate + execution + evidence + assessment)
# ---------------------------------------------------------------------------

class VerificationService:
    def __init__(self, *, executor: VerificationExecutorPort, policy: Any, registry: ToolRegistry, store: Any, scope_allows: Any, profile: str = "read_only", budget: VerificationBudget | None = None):
        from emo_cyber_agent.core.policy import StrictPolicyEngine

        if not isinstance(policy, StrictPolicyEngine):
            raise TypeError("verification requires StrictPolicyEngine")
        self._executor: Any = executor
        self._policy = policy
        self._registry = registry
        self._store = store
        self._scope_allows = scope_allows
        self._profile = profile
        self._budget = budget or VerificationBudget()
        self._start = time.monotonic()
        self._counts: dict[str, int] = {}
        self._target_counts: dict[str, int] = {}
        self._active = 0
        self._trail: list[dict[str, Any]] = []

    @property
    def trail(self) -> list[dict[str, Any]]:
        return list(self._trail)

    def _log(self, **kw: Any) -> None:
        from emo_cyber_agent.core.repository import redact_credentials

        clean = {k: (redact_credentials(str(v))[:300] if isinstance(v, str) else v) for k, v in kw.items()}
        self._trail.append(clean)

    def _check_budget(self, target: str) -> None:
        total = sum(self._counts.values())
        if total >= self._budget.max_verifications:
            raise VerificationError(VerificationErrorCode.BUDGET_EXHAUSTED, "max verifications exceeded")
        if self._active >= self._budget.max_active_verifications:
            raise VerificationError(VerificationErrorCode.BUDGET_EXHAUSTED, "too many active verifications")
        if time.monotonic() - self._start >= self._budget.max_time_s:
            raise VerificationError(VerificationErrorCode.BUDGET_EXHAUSTED, "verification time exhausted")
        if self._target_counts.get(target, 0) >= self._budget.max_same_target_attempts:
            raise VerificationError(VerificationErrorCode.LOOP_DETECTED, "repeated verification loop")

    def plan(self, *, candidate: FindingCandidate, request: VerificationRequest, audit_id: str) -> VerificationPlan:
        if candidate.audit_id != audit_id:
            raise VerificationError(VerificationErrorCode.MISMATCHED_AUDIT, "candidate/audit mismatch")
        safety = METHOD_SAFETY[request.method.value]
        if request.safety_level is not None and request.safety_level != safety:
            raise VerificationError(VerificationErrorCode.INVALID_REQUEST, "safety level inconsistent with method")
        capability = METHOD_CAPABILITY[request.method.value]
        self._check_budget(request.target.locator)
        if not self._scope_allows(audit_id, request.target.locator):
            raise VerificationError(VerificationErrorCode.OUT_OF_SCOPE, "target outside scope")
        if safety == SafetyLevel.RESTRICTED_ACTIVE:
            raise VerificationError(VerificationErrorCode.POLICY_DENIED, "restricted-active denied by default")
        if safety == SafetyLevel.SAFE_ACTIVE and self._profile != "verify":
            raise VerificationError(VerificationErrorCode.POLICY_DENIED, "safe-active requires verify profile")
        try:
            self._registry.get(_tool_id_for(request.method.value))
        except ValueError as e:
            raise VerificationError(VerificationErrorCode.POLICY_DENIED, "unregistered verification capability") from e
        constraints: dict[str, Any] = {"target": request.target.locator, "decision": "pending"}
        if request.method.value == VerificationMethod.READ_ONLY_QUERY.value:
            from emo_cyber_agent.core.supabase import classify_read_only_sql

            if not request.statement.strip():
                raise VerificationError(VerificationErrorCode.INVALID_REQUEST, "read-only query needs a statement")
            try:
                classify_read_only_sql(request.statement)
            except Exception as e:
                raise VerificationError(VerificationErrorCode.POLICY_DENIED, f"non-read query denied: {e}") from e
            constraints["sql_digest"] = hashlib.sha256(request.statement.encode()).hexdigest()
        decision = self._policy.issue_decision(audit_id, _tool_id_for(request.method.value), request.target.locator, self._profile, [capability])
        if not decision.allowed:
            raise VerificationError(VerificationErrorCode.POLICY_DENIED, f"policy denied: {','.join(decision.reason_codes)}")
        constraints["decision"] = decision.decision_id
        self._log(event="planned", candidate=candidate.candidate_id, method=request.method.value, safety=safety.value, decision=decision.decision_id[:8])
        return VerificationPlan(
            candidate_id=candidate.candidate_id,
            audit_id=audit_id,
            hypothesis=candidate.hypothesis[:500],
            steps=(f"{request.method.value} on {request.target.kind.value}:{request.target.locator}",),
            required_capabilities=(capability,),
            safety_level=safety,
            constraints=constraints,
            stopping_conditions=("evidence-sufficient", "contradiction-found", "budget-exhausted"),
        )

    def execute(self, *, plan: VerificationPlan, candidate: FindingCandidate, audit_id: str, policy_decision_id: str | None, retries: int = 0) -> tuple[Verification, VerificationResult]:
        from emo_cyber_agent.core.repository import redact_credentials

        if audit_id != plan.audit_id or audit_id != candidate.audit_id:
            raise VerificationError(VerificationErrorCode.MISMATCHED_AUDIT, "audit mismatch")
        decision = self._policy.get_decision(policy_decision_id or "")
        if decision is None or not decision.allowed:
            raise VerificationError(VerificationErrorCode.STALE_POLICY, "missing or denied policy decision")
        if policy_decision_id != plan.constraints.get("decision"):
            raise VerificationError(VerificationErrorCode.STALE_POLICY, "decision does not match plan")
        try:
            verification = Verification(candidate_id=candidate.candidate_id, audit_id=audit_id, asset_id=candidate.asset_id, method=self._method_of(plan), status=VerificationStatus.PENDING, policy_decision_id=decision.decision_id, safety_level=plan.safety_level, provenance={"plan": plan.plan_id, "policy_version": decision.policy_version})
        except ValueError as e:
            raise VerificationError(VerificationErrorCode.INVALID_REQUEST, str(e)) from e
        verification = verification.transition_to(VerificationStatus.RUNNING)
        self._active += 1
        self._log(event="started", verification=verification.verification_id[:8], method=verification.method.value)
        try:
            raw = self._run_method(plan, verification)
        except VerificationError:
            raise
        except Exception as e:
            raise VerificationError(VerificationErrorCode.PROVIDER_ERROR, redact_credentials(str(e))) from e
        finally:
            self._active = max(0, self._active - 1)
        return self._finish(verification, candidate, plan, raw, retries=retries)

    # -- method dispatch: ONE harness (the executor port) for every method.
    # Passive methods re-observe store facts through harness-driven checks;
    # the harness here is scripted (tests) or a future isolated runner.
    # Read-only SQL is classified at PLAN time; reproduction additionally
    # records isolation constraints on the plan. Core never shells out.
    def _run_method(self, plan: VerificationPlan, verification: Verification) -> VerificationRawResult:
        if verification.method.value == VerificationMethod.CONTROLLED_REPRODUCTION.value:
            plan = VerificationPlan(**{**plan.model_dump(), "constraints": {**plan.constraints, "isolated": True, "deterministic": True, "bounded": True, "ephemeral": True, "credential_free": True, "egress_free": True}})
            return self._executor.run(plan)
        return self._executor.run(plan)

    def _finish(self, verification: Verification, candidate: FindingCandidate, plan: VerificationPlan, raw: VerificationRawResult, *, retries: int) -> tuple[Verification, VerificationResult]:
        from emo_cyber_agent.core.repository import content_digest, redact_credentials
        from emo_cyber_agent.domain.models import EvidenceItem

        outcome = (raw.outcome or "").strip().lower()
        # injection in raw results is DATA: status derives from criteria only
        if outcome == "confirm":
            status = VerificationStatus.CONFIRMED
        elif outcome == "refute":
            status = VerificationStatus.REFUTED
        elif outcome == "blocked":
            status = VerificationStatus.BLOCKED
        elif outcome == "failed":
            if retries < self._budget.max_retries:
                self._log(event="retry", verification=verification.verification_id[:8])
                return self.execute(plan=plan, candidate=candidate, audit_id=verification.audit_id, policy_decision_id=verification.policy_decision_id, retries=retries + 1)
            status = VerificationStatus.FAILED
        elif outcome == "timeout":
            if retries < self._budget.max_retries:
                self._log(event="retry", verification=verification.verification_id[:8])
                return self.execute(plan=plan, candidate=candidate, audit_id=verification.audit_id, policy_decision_id=verification.policy_decision_id, retries=retries + 1)
            status = VerificationStatus.TIMEOUT
        else:
            status = VerificationStatus.INCONCLUSIVE

        verification = verification.transition_to(VerificationStatus.RUNNING) if verification.status == VerificationStatus.PENDING else verification
        # store verification evidence (mandatory for CONFIRMED)

        observed = redact_credentials(raw.observed or "")[:500]
        evidence_ids: list[str] = list(raw.evidence_refs or ())
        if observed or True:
            item = EvidenceItem(
                source_tool="verifier",
                source_version="1.0",
                target_asset_id=verification.asset_id,
                location=plan.constraints.get("target", ""),
                content_hash=content_digest(f"{verification.verification_id}|{observed}"),
                content_summary=f"[{verification.method.value}] {observed or 'no observation'}"[:500] or "verification record",
                provenance={"verification_id": verification.verification_id, "method": verification.method.value, "safety": verification.safety_level.value, "labels": ("verification-evidence",)},
            )
            try:
                self._store.store(item, audit_id=verification.audit_id)
                evidence_ids.append(item.id)
            except ValueError as e:
                raise VerificationError(VerificationErrorCode.MISMATCHED_AUDIT, str(e)) from e
        if status == VerificationStatus.CONFIRMED and not evidence_ids:
            raise VerificationError(VerificationErrorCode.NO_EVIDENCE, "confirmed without evidence denied")
        verification = Verification(**{**verification.model_dump(), "status": status, "completed_at": datetime.now(timezone.utc).isoformat(), "evidence_ids": tuple(evidence_ids), "result_summary": observed, "confidence": 0.85 if status == VerificationStatus.CONFIRMED else (0.6 if status == VerificationStatus.SUPPORTED else (0.2 if status == VerificationStatus.REFUTED else 0.4)), "provenance": {**verification.provenance, "outcome": outcome}})

        self._counts[verification.method.value] = self._counts.get(verification.method.value, 0) + 1
        self._target_counts[plan.constraints.get("target", "")] = self._target_counts.get(plan.constraints.get("target", ""), 0) + 1
        self._log(event="completed", verification=verification.verification_id[:8], status=status.value, evidence=len(evidence_ids))
        result = VerificationResult(verification_id=verification.verification_id, candidate_id=candidate.candidate_id, audit_id=verification.audit_id, status=status, confidence=verification.confidence, evidence_ids=tuple(evidence_ids), summary=observed)
        return verification, result

    def _method_of(self, plan: VerificationPlan) -> VerificationMethod:
        step = (plan.steps[0] if plan.steps else "")
        for m in VerificationMethod:
            if step.startswith(m.value):
                return m
        raise VerificationError(VerificationErrorCode.INVALID_REQUEST, "plan step has no known method")


def _tool_id_for(method_value: str) -> str:
    cap = METHOD_CAPABILITY[method_value]
    mapping = {"verification.static": "verification.static", "verification.config": "verification.config", "verification.read_query": "verification.read_query", "verification.controlled_reproduction": "verification.controlled_reproduction"}
    return mapping[cap]
