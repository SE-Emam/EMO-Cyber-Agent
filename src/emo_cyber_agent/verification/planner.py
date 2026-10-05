"""Verification strategy planner — POST-RC-012.

Pure Core decision logic: hypothesis + evidence + target + policy
→ one deterministic strategy, one bound adapter, one bounded
budget, one typed oracle → policy-bound plan → bounded dispatch.

The model only ever suggests. Selection is table-driven, sorted,
and identical across runs. The planner writes no findings, assigns
no severity, and never leaves the declared scope: `dispatch` is the
single Core-side execution boundary in this layer.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.threat_modeling.spec import canonical_digest
from emo_cyber_agent.verification.adapter_contracts import (
    OperationalResult,
    VerificationAdapter,
    VerificationAdapterRequest,
    VerificationAdapterResponse,
    flag_authority_language,
)
from emo_cyber_agent.verification.adapter_provenance import (
    assert_provenance_binds,
    provenance_of,
)
from emo_cyber_agent.verification.adapter_resolver import (
    AdapterBinding,
    VerificationAdapterResolver,
    assert_adapter_available,
    assert_request_matches_binding,
)
from emo_cyber_agent.verification.budget import (
    BudgetUsage,
    ResourceBudget,
    effective_budget,
    retry_kind,
)
from emo_cyber_agent.verification.coverage import (
    CoverageAssessment,
    VerificationControls,
    assess_coverage,
)
from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode
from emo_cyber_agent.verification.evidence import EvidenceCriteria, EvidenceOracle, build_evidence
from emo_cyber_agent.verification.matrix import VerificationMatrix, row_oracle_subject
from emo_cyber_agent.verification.oracles import (
    OracleOutcome,
    VerificationOracle,
    evaluate_oracle,
    oracle_subject_of,
)
from emo_cyber_agent.verification.strategy import (
    _SAFETY_RANK,
    SAFETY_LEVELS,
    StrategyCatalog,
    StrategyTarget,
    VerificationStrategy,
)

# One Core capability per strategy — least privilege, decided here,
# never by the provider or the caller.
_CATEGORY_CAPABILITY: dict[str, str] = {
    "PASSIVE_PROPERTY_CHECK": "verification.static",
    "STATIC_PROPERTY_CHECK": "verification.static",
    "STRUCTURAL_CONSISTENCY": "verification.static",
    "DEPENDENCY_ASSERTION": "verification.static",
    "SECRET_EXPOSURE_CHECK": "verification.static",
    "REGRESSION_CHECK": "verification.static",
    "CONFIGURATION_CHECK": "verification.config",
    "DATA_FLOW_CONFIRMATION": "verification.config",
    "AUTHORIZATION_MATRIX": "verification.controlled_reproduction",
    "AUTHENTICATION_FLOW": "verification.controlled_reproduction",
    "INPUT_BOUNDARY": "verification.controlled_reproduction",
    "OUTPUT_BOUNDARY": "verification.controlled_reproduction",
    "NETWORK_BEHAVIOR_CHECK": "verification.controlled_reproduction",
    "STATE_CHANGE_CHECK": "verification.controlled_reproduction",
    "SAFE_ACTIVE_REQUEST": "verification.controlled_reproduction",
    "NEGATIVE_TEST": "verification.controlled_reproduction",
    "POSITIVE_CONTROL": "verification.controlled_reproduction",
    "CONTROLLED_REPRODUCTION": "verification.controlled_reproduction",
}

# Default expected value per oracle kind. Deny-by-default: an
# authorization oracle with no declared expectation means DENY.
_DEFAULT_EXPECTED: dict[str, str] = {
    "AUTHZ_DECISION": "deny",
    "CONFIG_PROPERTY": "true",
    "FILE_STATE_PROPERTY": "false",
    "GRAPH_PROPERTY": "false",
    "HEADER_PROPERTY": "",
    "HTTP_STATUS": "",
    "HTTP_BODY_PROPERTY": "",
    "DATABASE_STATE_PROPERTY": "",
    "PROCESS_EXIT": "0",
    "STRUCTURED_TOOL_RESULT": "matches-declared",
    "CUSTOM_ASSERTION": "",
}

PLAN_STATUSES: tuple[str, ...] = ("SUPPORTED", "REFUTED", "INCONCLUSIVE", "NOT_RUN", "BLOCKED")
OPERATIONAL_ONLY_STATUSES: tuple[str, ...] = ("INCONCLUSIVE", "BLOCKED", "NOT_RUN")


class VerificationStrategyPlan(BaseModel):
    """Frozen, deterministic plan. No timestamps: the same inputs
    always digest to the same plan."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    plan_id: str = Field(default="", max_length=120)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    hypothesis_kind: str = Field(..., min_length=1, max_length=60)
    statement: str = Field(default="", max_length=1000)
    target: StrategyTarget
    strategy_id: str = Field(..., min_length=1, max_length=80)
    strategy_version: str = Field(..., min_length=1, max_length=40)
    strategy_digest: str = Field(..., min_length=1, max_length=128)
    strategy_category: str = Field(..., min_length=1, max_length=60)
    adapter_id: str = Field(default="", max_length=80)
    adapter_version: str = Field(default="", max_length=40)
    adapter_contract_version: str = Field(default="1.0", max_length=40)
    oracle: VerificationOracle
    safety_level: str = Field(..., min_length=1, max_length=40)
    required_capabilities: tuple[str, ...] = ()
    core_capability: str = Field(..., min_length=1, max_length=80)
    resource_budget: ResourceBudget = Field(default_factory=ResourceBudget)
    success_criteria: str = Field(..., min_length=1, max_length=500)
    refutation_criteria: str = Field(..., min_length=1, max_length=500)
    available_evidence: tuple[str, ...] = ()
    controls: VerificationControls = Field(default_factory=VerificationControls)
    policy_decision_id: str = Field(..., min_length=1, max_length=120)
    policy_version: str = Field(..., min_length=1, max_length=60)
    selection_notes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    digest: str = Field(default="", max_length=128)

    @field_validator("safety_level")
    @classmethod
    def _safety(cls, v: str) -> str:
        if v not in SAFETY_LEVELS:
            raise ValueError(f"safety level not allowed: {v}")
        return v

    def model_post_init(self, __context: Any, /) -> None:
        payload = self.model_dump(mode="json", exclude={"digest", "plan_id", "policy_decision_id"})
        digest = canonical_digest(payload)
        if not self.digest:
            object.__setattr__(self, "digest", digest)
        if not self.plan_id:
            object.__setattr__(self, "plan_id", f"vplan-{digest[:24]}")


class StrategyVerificationResult(BaseModel):
    """Closed result vocabulary. Operational outcomes map only to
    INCONCLUSIVE/BLOCKED/NOT_RUN — never to a security verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    verification_id: str = Field(..., min_length=1, max_length=120)
    plan_id: str = Field(..., min_length=1, max_length=120)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    status: str
    operational_result: str = OperationalResult.OK.value
    oracle_outcome: str = ""
    oracle_reason: str = Field(default="", max_length=80)
    coverage: CoverageAssessment
    evidence_id: str = Field(default="", max_length=128)
    provenance: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    data_flags: tuple[str, ...] = ()
    retry_class: str = Field(default="NONE", max_length=32)
    digest: str = Field(default="", max_length=128)

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in PLAN_STATUSES:
            raise ValueError(f"status not allowed: {v}")
        return v

    @field_validator("oracle_outcome")
    @classmethod
    def _outcome(cls, v: str) -> str:
        if v and v not in tuple(member.value for member in OracleOutcome):
            raise ValueError(f"oracle outcome not allowed: {v}")
        return v

    @field_validator("retry_class")
    @classmethod
    def _retry(cls, v: str) -> str:
        if v not in ("NONE", "OPERATIONAL_RETRY", "SECURITY_RETRY"):
            raise ValueError(f"retry class not allowed: {v}")
        return v

    def model_post_init(self, __context: Any, /) -> None:
        if not self.digest:
            object.__setattr__(self, "digest", canonical_digest(self.model_dump(mode="json", exclude={"digest"})))

    @property
    def security_result(self) -> str:
        return self.status

    @property
    def is_operational_only(self) -> bool:
        return self.status in OPERATIONAL_ONLY_STATUSES

    def eligibility(self) -> dict[str, Any]:
        """Handoff data only: the planner never creates a Finding.
        Downstream evaluation (thresholds, policy, lifecycle) stays
        with FindingService under its own contract."""
        return {
            "verification_id": self.verification_id,
            "plan_id": self.plan_id,
            "status": self.status,
            "coverage": self.coverage.coverage,
            "evidence_id": self.evidence_id,
            "eligible_for_finding_evaluation": self.status == "SUPPORTED" and bool(self.evidence_id),
            "reasons": tuple(self.coverage.limitations) + tuple(self.limitations),
            "severity": None,
        }

    @classmethod
    def not_run(cls, plan: VerificationStrategyPlan, reason: str) -> StrategyVerificationResult:
        controls = plan.controls
        coverage = assess_coverage(
            oracle_outcome="",
            controls=controls,
            operational_result=OperationalResult.POLICY_DENIED.value,
            response_coverage="none",
            limitations=(reason,),
        )
        return cls(
            verification_id=f"{plan.plan_id}-n1",
            plan_id=plan.plan_id,
            audit_id=plan.audit_id,
            project_id=plan.project_id,
            snapshot_id=plan.snapshot_id,
            status="NOT_RUN",
            operational_result=OperationalResult.POLICY_DENIED.value,
            coverage=coverage,
            provenance={"plan_digest": plan.digest, "strategy": f"{plan.strategy_id}@{plan.strategy_version}"},
            limitations=(reason,),
            retry_class="SECURITY_RETRY" if reason == "policy-denied" else "NONE",
        )


class VerificationPlanner:
    """Core-owned planner. Selection is deterministic; the model may
    suggest but never decides."""

    def __init__(
        self,
        *,
        catalog: StrategyCatalog,
        matrix: VerificationMatrix,
        resolver: VerificationAdapterResolver,
        policy: Any,
        profile: str = "read_only",
        runtime_budget: ResourceBudget | None = None,
    ) -> None:
        from emo_cyber_agent.core.policy import StrictPolicyEngine

        if not isinstance(policy, StrictPolicyEngine):
            raise TypeError("verification planning requires StrictPolicyEngine")
        if profile not in ("read_only", "verify"):
            raise ValueError("profile must be read_only or verify")
        self._catalog = catalog
        self._matrix = matrix
        self._resolver = resolver
        self._policy = policy
        self._profile = profile
        self._runtime_budget = runtime_budget or ResourceBudget()

    @property
    def profile(self) -> str:
        return self._profile

    def _levels_allowed(self) -> tuple[str, ...]:
        return ("PASSIVE", "SAFE_ACTIVE") if self._profile == "verify" else ("PASSIVE",)

    def _capability_for(self, strategy: VerificationStrategy) -> str:
        try:
            return _CATEGORY_CAPABILITY[strategy.category]
        except KeyError as e:
            raise StrategyError(StrategyErrorCode.INVALID_STRATEGY, f"no capability mapping: {strategy.category}") from e

    def _issue_decision(self, *, audit_id: str, capability: str, target: StrategyTarget) -> Any:
        target_label = f"{target.kind.lower()}:{target.object_identity}"
        if not self._policy.check_scope(audit_id, target_label):
            raise StrategyError(StrategyErrorCode.SCOPE_DENIED, "target outside declared scope")
        decision = self._policy.issue_decision(audit_id, capability, target_label, self._profile, [capability])
        if not decision.allowed:
            raise StrategyError(StrategyErrorCode.POLICY_DENIED, f"policy denied: {','.join(decision.reason_codes)}")
        return decision

    def _build_oracle(
        self,
        *,
        kind: str,
        row_subject: str,
        expected: str,
        assertion: str,
        strategy: VerificationStrategy,
    ) -> VerificationOracle:
        if kind not in strategy.oracle_contract:
            raise StrategyError(StrategyErrorCode.ORACLE_REJECTED, f"strategy {strategy.id} does not contract {kind}")
        want = expected if expected else _DEFAULT_EXPECTED.get(kind, "")
        if kind not in ("CUSTOM_ASSERTION",) and want == "" and not assertion:
            raise StrategyError(StrategyErrorCode.ORACLE_REJECTED, f"oracle of kind {kind} needs an expected value")
        try:
            oracle = VerificationOracle(kind=kind, subject=row_subject, operator="EQUALS", expected=want, assertion=assertion)
        except ValueError as e:
            raise StrategyError(StrategyErrorCode.ORACLE_REJECTED, str(e)) from e
        if not strategy.supports_oracle(oracle.kind):
            raise StrategyError(StrategyErrorCode.ORACLE_REJECTED, f"oracle not in strategy contract: {oracle.kind}")
        return oracle

    def plan(
        self,
        *,
        audit_id: str,
        project_id: str,
        snapshot_id: str,
        target: StrategyTarget,
        hypothesis_kind: str,
        statement: str = "",
        available_evidence: tuple[str, ...] = (),
        expected: str = "",
        assertion: str = "",
        model_suggestion: str = "",
        controls: VerificationControls | None = None,
        limitations: tuple[str, ...] = (),
    ) -> VerificationStrategyPlan:
        if target.audit_id != audit_id:
            raise StrategyError(StrategyErrorCode.AUDIT_MISMATCH, "target audit does not match plan audit")
        if target.project_id != project_id:
            raise StrategyError(StrategyErrorCode.AUDIT_MISMATCH, "target project does not match plan project")
        if target.snapshot_id != snapshot_id:
            raise StrategyError(StrategyErrorCode.SNAPSHOT_MISMATCH, "target snapshot does not match plan snapshot")

        row = self._matrix.row(hypothesis_kind)
        missing = [e for e in row.required_evidence if e not in available_evidence]
        if missing:
            raise StrategyError(StrategyErrorCode.SELECTION_FAILED, f"missing required evidence: {','.join(missing)}")

        notes: list[str] = []
        skipped: list[str] = []
        selected: tuple[VerificationStrategy, Any, str] | None = None
        candidates = sorted(
            (sid for sid in row.candidate_strategies if sid in set(self._catalog.ids())),
            key=lambda sid: (self._catalog.get(sid).max_safety_level, sid),
        )
        for strategy_id in candidates:
            try:
                strategy = self._catalog.get(strategy_id)
            except StrategyError:
                skipped.append(f"{strategy_id}:unknown")
                continue
            if not strategy.supports_target(target.kind):
                skipped.append(f"{strategy_id}:target-kind")
                continue
            levels = [level for level in strategy.allowed_safety_levels if level in self._levels_allowed()]
            if not levels:
                skipped.append(f"{strategy_id}:profile-level")
                continue
            strategy_missing = [e for e in strategy.required_evidence if e not in available_evidence]
            if strategy_missing:
                skipped.append(f"{strategy_id}:evidence")
                continue
            if row.oracle_kind not in strategy.oracle_contract:
                skipped.append(f"{strategy_id}:oracle-contract")
                continue
            try:
                bound = self._resolver.resolve(strategy, target_kind=target.kind)
            except StrategyError:
                skipped.append(f"{strategy_id}:no-adapter")
                continue
            level = min(levels, key=lambda value: _SAFETY_RANK[value])
            selected = (strategy, bound, level)
            break

        if selected is None:
            raise StrategyError(
                StrategyErrorCode.SELECTION_FAILED,
                f"no selectable strategy for {hypothesis_kind} on {target.kind}: {';'.join(skipped) or 'no-candidates'}",
            )
        strategy, bound, level = selected

        if model_suggestion:
            if model_suggestion == strategy.id:
                notes.append("model-suggestion:matches-deterministic-selection")
            elif model_suggestion in row.candidate_strategies:
                notes.append("model-suggestion:recorded-selection-remains-deterministic")
            else:
                notes.append("model-suggestion:ignored-outside-candidates")

        oracle = self._build_oracle(
            kind=row.oracle_kind,
            row_subject=row_oracle_subject(row),
            expected=expected,
            assertion=assertion,
            strategy=strategy,
        )
        capability = self._capability_for(strategy)
        decision = self._issue_decision(audit_id=audit_id, capability=capability, target=target)
        budget = effective_budget(strategy.resource_budget, self._runtime_budget)
        notes.extend(f"candidate-skipped:{entry}" for entry in skipped[:6])

        return VerificationStrategyPlan(
            audit_id=audit_id,
            project_id=project_id,
            snapshot_id=snapshot_id,
            hypothesis_kind=hypothesis_kind,
            statement=statement[:1000],
            target=target,
            strategy_id=strategy.id,
            strategy_version=strategy.version,
            strategy_digest=strategy.digest,
            strategy_category=strategy.category,
            adapter_id=bound.binding.adapter_id,
            adapter_version=bound.binding.adapter_version,
            adapter_contract_version=bound.binding.contract_version,
            oracle=oracle,
            safety_level=level,
            required_capabilities=tuple(strategy.required_capabilities),
            core_capability=capability,
            resource_budget=budget,
            success_criteria=strategy.success_criteria,
            refutation_criteria=strategy.refutation_criteria,
            available_evidence=tuple(dict.fromkeys(available_evidence)),
            controls=controls or VerificationControls(),
            policy_decision_id=decision.decision_id,
            policy_version=decision.policy_version,
            selection_notes=tuple(notes),
            limitations=tuple(limitations),
        )

    def dispatch(
        self,
        plan: VerificationStrategyPlan,
        *,
        adapter: VerificationAdapter,
        attempts: int = 1,
        budget_usage: BudgetUsage | None = None,
    ) -> StrategyVerificationResult:
        """The one Core-side execution boundary of this layer. Policy,
        scope, binding, health, and budget are re-checked here — a
        plan alone never grants execution."""
        decision = self._policy.get_decision(plan.policy_decision_id)
        if decision is None:
            raise StrategyError(StrategyErrorCode.STALE_POLICY, "policy decision is not retrievable")
        if not decision.allowed:
            raise StrategyError(StrategyErrorCode.POLICY_DENIED, "policy decision no longer allows execution")
        if decision.policy_version != plan.policy_version:
            raise StrategyError(StrategyErrorCode.STALE_POLICY, "policy version changed since planning")
        if decision.audit_id != plan.audit_id:
            raise StrategyError(StrategyErrorCode.AUDIT_MISMATCH, "policy decision audit mismatch")
        if plan.safety_level == "RESTRICTED_ACTIVE":
            raise StrategyError(StrategyErrorCode.UNSAFE_LEVEL, "restricted-active denied by default")
        if plan.safety_level == "SAFE_ACTIVE" and self._profile != "verify":
            raise StrategyError(StrategyErrorCode.POLICY_DENIED, "safe-active requires verify profile")

        self._resolver.check_binding(_plan_binding(plan), adapter=adapter)
        assert_adapter_available(adapter)
        if not self._policy.check_scope(plan.audit_id, f"{plan.target.kind.lower()}:{plan.target.object_identity}"):
            raise StrategyError(StrategyErrorCode.SCOPE_DENIED, "target outside declared scope")

        usage = budget_usage or BudgetUsage(max_requests=max(1, attempts), max_attempts=max(1, attempts))
        plan.resource_budget.used(usage)

        verification_id = f"{plan.plan_id}-e{max(1, attempts)}"
        request = VerificationAdapterRequest(
            verification_id=verification_id,
            strategy_id=plan.strategy_id,
            strategy_version=plan.strategy_version,
            audit_id=plan.audit_id,
            project_id=plan.project_id,
            snapshot_id=plan.snapshot_id,
            target_kind=plan.target.kind,
            target_identity=plan.target.object_identity,
            normalized_inputs={
                "oracle": plan.oracle.model_dump(mode="json"),
                "subject": oracle_subject_of(plan.oracle),
                "expected": plan.oracle.expected,
                "hypothesis_kind": plan.hypothesis_kind,
                "success_criteria": plan.success_criteria,
            },
            required_capabilities=tuple(plan.required_capabilities),
            safety_level=plan.safety_level,
            budget={
                "max_requests": plan.resource_budget.max_requests,
                "max_duration_s": plan.resource_budget.max_duration_s,
                "max_output_bytes": plan.resource_budget.max_output_bytes,
            },
            oracle_contract=(plan.oracle.kind,),
            policy_decision_id=plan.policy_decision_id,
            correlation_context={"plan_id": plan.plan_id},
        )
        assert_request_matches_binding(
            request,
            _plan_binding(plan),
            snapshot_id=plan.snapshot_id,
            audit_id=plan.audit_id,
            project_id=plan.project_id,
            policy_decision_id=plan.policy_decision_id,
        )
        adapter.validate(request)
        response = adapter.execute(request)
        return self._interpret(plan=plan, response=response, verification_id=verification_id, adapter=adapter)

    def _interpret(
        self,
        *,
        plan: VerificationStrategyPlan,
        response: VerificationAdapterResponse,
        verification_id: str,
        adapter: VerificationAdapter,
    ) -> StrategyVerificationResult:
        if response.verification_id != verification_id:
            raise StrategyError(StrategyErrorCode.ADAPTER_UNVERIFIABLE, "response verification identity mismatch")
        if response.adapter_id != plan.adapter_id or response.adapter_version != plan.adapter_version:
            raise StrategyError(StrategyErrorCode.ADAPTER_VERSION_MISMATCH, "response adapter identity mismatch")
        if response.status in ("MALFORMED",):
            raise StrategyError(StrategyErrorCode.ADAPTER_INVALID_REQUEST, "adapter returned malformed output")
        provenance = provenance_of(response)
        assert_provenance_binds(
            provenance,
            adapter_id=plan.adapter_id,
            adapter_version=plan.adapter_version,
            policy_decision_id=plan.policy_decision_id,
        )

        operational = response.operational_result
        if operational != OperationalResult.OK.value:
            status = "BLOCKED" if operational == OperationalResult.POLICY_DENIED.value else "INCONCLUSIVE"
            outcome, reason = "", f"operational:{operational.lower()}"
        else:
            judged, reason = evaluate_oracle(plan.oracle, dict(response.oracle_inputs))
            status = judged.value
            outcome = judged.value

        data_flags = tuple(
            dict.fromkeys(
                (*response.data_flags, *flag_authority_language(response.normalized_output, *[str(v) for v in response.observations.values()]))
            )
        )
        coverage = assess_coverage(
            oracle_outcome=outcome or "INCONCLUSIVE",
            controls=plan.controls,
            operational_result=operational,
            response_coverage=response.coverage,
            limitations=tuple(response.limitations),
        )
        evidence = build_evidence(
            verification_id=verification_id,
            strategy_id=plan.strategy_id,
            strategy_version=plan.strategy_version,
            adapter_id=plan.adapter_id,
            adapter_version=plan.adapter_version,
            target_kind=plan.target.kind,
            target_identity=plan.target.object_identity,
            snapshot_id=plan.snapshot_id,
            audit_id=plan.audit_id,
            project_id=plan.project_id,
            observed=response.normalized_output,
            oracle=EvidenceOracle(
                kind=plan.oracle.kind,
                subject=plan.oracle.subject,
                operator=plan.oracle.operator,
                expected=plan.oracle.expected,
                assertion=plan.oracle.assertion,
                outcome=outcome or "NONE",
                reason_code=reason,
            ),
            criteria=EvidenceCriteria(success=plan.success_criteria, refutation=plan.refutation_criteria),
            coverage={"complete": "complete", "partial": "partial", "limited": "limited"}.get(response.coverage, "unknown"),
            limitations=tuple(response.limitations),
            data_flags=data_flags,
            provenance={
                "plan_id": plan.plan_id,
                "plan_digest": plan.digest,
                "strategy": f"{plan.strategy_id}@{plan.strategy_version}",
                "adapter": f"{plan.adapter_id}@{plan.adapter_version}",
                "policy_decision_id": plan.policy_decision_id,
                "provider_identity": provenance.provider_identity,
                "provider_version": provenance.provider_version,
                "trace": list(provenance.trace),
                "raw_digest": response.raw_digest,
            },
        )
        return StrategyVerificationResult(
            verification_id=verification_id,
            plan_id=plan.plan_id,
            audit_id=plan.audit_id,
            project_id=plan.project_id,
            snapshot_id=plan.snapshot_id,
            status=status,
            operational_result=operational,
            oracle_outcome=outcome,
            oracle_reason=reason,
            coverage=coverage,
            evidence_id=evidence.digest[:64],
            provenance={
                "trace": list(provenance.trace),
                "strategy": f"{plan.strategy_id}@{plan.strategy_version}",
                "adapter": f"{plan.adapter_id}@{plan.adapter_version}",
                "policy_decision_id": plan.policy_decision_id,
                "plan_digest": plan.digest,
            },
            limitations=tuple(dict.fromkeys(tuple(response.limitations) + tuple(plan.limitations))),
            data_flags=data_flags,
            retry_class=retry_kind(reason=reason.removeprefix("operational:").replace("_", "-")) if operational != OperationalResult.OK.value else "NONE",
        )


def _plan_binding(plan: VerificationStrategyPlan) -> AdapterBinding:
    """The binding frozen at planning time. A swapped adapter can only
    fail this check, never redefine it."""
    return AdapterBinding(
        adapter_id=plan.adapter_id,
        adapter_version=plan.adapter_version,
        strategy_id=plan.strategy_id,
        strategy_version=plan.strategy_version,
        contract_version=plan.adapter_contract_version,
    )
