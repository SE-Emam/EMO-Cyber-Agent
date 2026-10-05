"""Security Reasoning Engine & Agent Loop — ECA-T009.

Model proposes → Core validates → StrictPolicy authorizes → ToolRegistry
resolves → Tool executes → Evidence informs → Correlation updates → Model.
The model is NEVER the security authority; that chain is enforced in code,
not documentation.

Analysis-only loop: produces SecurityObservations + FindingCandidates via
the ECA-T008 correlation engine. No final Findings, no verification
execution (REQUEST_VERIFICATION is a proposal only), no remediation.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.core.correlation import (
    CorrelationEngine,
    FindingCandidate,
    SecurityObservation,
    compute_confidence,
)
from emo_cyber_agent.core.policy import StrictPolicyEngine
from emo_cyber_agent.core.tool_registry import ToolRegistry

LOOP_VERSION = "eca-t009-v1"
MAX_SUMMARY_CHARS = 2000
MAX_ACTIONS_PER_RESPONSE = 5


class SessionStatus(StrEnum):
    INITIALIZING = "initializing"
    OBSERVING = "observing"
    HYPOTHESIZING = "hypothesizing"
    PLANNING = "planning"
    REQUESTING_ACTION = "requesting_action"
    WAITING_FOR_RESULT = "waiting_for_result"
    CORRELATING = "correlating"
    REASSESSING = "reassessing"
    CONCLUDING = "concluding"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"
    USER_STOPPED = "user_stopped"


TERMINAL = frozenset({SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.BLOCKED, SessionStatus.BUDGET_EXHAUSTED, SessionStatus.USER_STOPPED})

_VALID_TRANSITIONS: dict[SessionStatus, frozenset[SessionStatus]] = {
    SessionStatus.INITIALIZING: frozenset({SessionStatus.OBSERVING, SessionStatus.FAILED, SessionStatus.BLOCKED}),
    SessionStatus.OBSERVING: frozenset({SessionStatus.HYPOTHESIZING, SessionStatus.CONCLUDING, SessionStatus.FAILED, SessionStatus.BLOCKED, SessionStatus.BUDGET_EXHAUSTED}),
    SessionStatus.HYPOTHESIZING: frozenset({SessionStatus.PLANNING, SessionStatus.CONCLUDING, SessionStatus.FAILED, SessionStatus.BLOCKED, SessionStatus.BUDGET_EXHAUSTED}),
    SessionStatus.PLANNING: frozenset({SessionStatus.REQUESTING_ACTION, SessionStatus.REASSESSING, SessionStatus.OBSERVING, SessionStatus.CORRELATING, SessionStatus.CONCLUDING, SessionStatus.FAILED, SessionStatus.BLOCKED, SessionStatus.BUDGET_EXHAUSTED}),
    SessionStatus.REQUESTING_ACTION: frozenset({SessionStatus.WAITING_FOR_RESULT, SessionStatus.REASSESSING, SessionStatus.FAILED, SessionStatus.BLOCKED, SessionStatus.BUDGET_EXHAUSTED}),
    SessionStatus.WAITING_FOR_RESULT: frozenset({SessionStatus.CORRELATING, SessionStatus.REASSESSING, SessionStatus.FAILED, SessionStatus.BLOCKED, SessionStatus.BUDGET_EXHAUSTED}),
    SessionStatus.CORRELATING: frozenset({SessionStatus.REASSESSING, SessionStatus.FAILED, SessionStatus.BLOCKED, SessionStatus.BUDGET_EXHAUSTED}),
    SessionStatus.REASSESSING: frozenset({SessionStatus.OBSERVING, SessionStatus.CONCLUDING, SessionStatus.FAILED, SessionStatus.BLOCKED, SessionStatus.BUDGET_EXHAUSTED}),
    SessionStatus.CONCLUDING: frozenset({SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.BLOCKED}),
    SessionStatus.COMPLETED: frozenset(),
    SessionStatus.FAILED: frozenset(),
    SessionStatus.BLOCKED: frozenset(),
    SessionStatus.BUDGET_EXHAUSTED: frozenset(),
    SessionStatus.USER_STOPPED: frozenset(),
}


class InvestigationPhase(StrEnum):
    RECON = "recon"
    ATTACK_SURFACE = "attack_surface"
    AUTH = "auth"
    AUTHORIZATION = "authorization"
    INPUT_HANDLING = "input_handling"
    DATA_ACCESS = "data_access"
    DEPENDENCIES = "dependencies"
    SECRETS = "secrets"
    CONFIGURATION = "configuration"
    SUPPLY_CHAIN = "supply_chain"
    BUSINESS_LOGIC = "business_logic"
    CROSS_LAYER = "cross_layer"
    REVIEW = "review"


class ActionKind(StrEnum):
    OBSERVE = "observe"
    SEARCH = "search"
    READ = "read"
    SCAN = "scan"
    CORRELATE = "correlate"
    REQUEST_VERIFICATION = "request_verification"
    CONCLUDE = "conclude"


class FailureCode(StrEnum):
    MODEL_UNAVAILABLE = "model_unavailable"
    MODEL_INVALID_RESPONSE = "model_invalid_response"
    ACTION_REJECTED = "action_rejected"
    POLICY_DENIED = "policy_denied"
    TOOL_UNAVAILABLE = "tool_unavailable"
    TOOL_FAILED = "tool_failed"
    NO_PROGRESS = "no_progress"
    LOOP_DETECTED = "loop_detected"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CONTEXT_LIMIT = "context_limit"
    SECURITY_BLOCKED = "security_blocked"


class HypothesisStatus(StrEnum):
    OPEN = "open"
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    NEEDS_EVIDENCE = "needs_evidence"
    DISMISSED = "dismissed"
    PROMOTABLE = "promotable"


class LoopBudget(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    max_iterations: int = Field(default=12, ge=1, le=100)
    max_tool_calls: int = Field(default=8, ge=0, le=50)
    max_wall_time_s: int = Field(default=300, ge=1, le=3600)
    max_evidence_context: int = Field(default=20, ge=1, le=100)
    max_repeated_action_count: int = Field(default=2, ge=1, le=10)
    no_progress_limit: int = Field(default=2, ge=1, le=10)


class ReasoningSession(BaseModel):
    """Session-scoped: can never observe another audit's job."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: str = Field(..., min_length=1)
    phase: InvestigationPhase = InvestigationPhase.RECON
    status: SessionStatus = SessionStatus.INITIALIZING
    iteration: int = Field(default=0, ge=0)
    budget: LoopBudget = Field(default_factory=LoopBudget)
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hypothesis_ids: tuple[str, ...] = ()
    evidence_context_id: str = ""
    action_ids: tuple[str, ...] = ()
    termination_reason: str = ""
    tool_calls: int = Field(default=0, ge=0)
    no_progress_streak: int = Field(default=0, ge=0)

    def transition_to(self, new: SessionStatus, *, reason: str = "") -> ReasoningSession:
        # Transitions never consume budget by themselves; the engine counts
        # one iteration per observe→…→reassess pass in run().
        if new not in _VALID_TRANSITIONS[self.status]:
            raise ValueError(f"invalid session transition {self.status.value} → {new.value}")
        data = self.model_dump()
        data.update(status=new, updated_at=datetime.now(timezone.utc).isoformat())
        if new in TERMINAL and reason:
            data["termination_reason"] = reason[:300]
        return ReasoningSession(**data)


class ReasonerAction(BaseModel):
    """Typed action proposal. Structured parameters only — never raw shell."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    kind: ActionKind
    tool_id: str = ""
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(..., min_length=1)
    expected_evidence: str = ""

    @field_validator("parameters")
    @classmethod
    def _no_shell_fields(cls, v: dict[str, Any]) -> dict[str, Any]:
        banned = {"command", "shell", "script", "cmd", "exec", "system", "eval"}
        hit = banned & {str(k).lower() for k in v}
        if hit:
            raise ValueError(f"raw-shell fields denied: {sorted(hit)}")
        return v


class HypothesisDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    category: str = ""
    statement: str = Field(..., min_length=1)
    evidence_refs: tuple[str, ...] = ()


class ReasonerResponse(BaseModel):
    """Structured model output. Free text is never interpreted as command."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    response_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = Field(..., min_length=1)
    analysis_summary: str = Field(default="", max_length=MAX_SUMMARY_CHARS)
    hypotheses: tuple[HypothesisDraft, ...] = ()
    next_actions: tuple[ReasonerAction, ...] = Field(default_factory=tuple)
    requested_observations: tuple[str, ...] = ()
    uncertainty: float = Field(default=0.5, ge=0.0, le=1.0)
    termination_request: bool = False

    @field_validator("next_actions")
    @classmethod
    def _bounded(cls, v: tuple[ReasonerAction, ...]) -> tuple[ReasonerAction, ...]:
        if len(v) > MAX_ACTIONS_PER_RESPONSE:
            raise ValueError("too many actions proposed")
        return v


class SecurityHypothesis(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    hypothesis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: str = Field(..., min_length=1)
    category: str = ""
    statement: str = Field(..., min_length=1)
    supporting_evidence_ids: tuple[str, ...] = ()
    contradicting_evidence_ids: tuple[str, ...] = ()
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: HypothesisStatus = HypothesisStatus.OPEN
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReasonerProvider(ABC):
    """Model boundary. Receives context+state+caps+objective; returns a
    structured response. Cannot execute tools, raise permission, touch
    policy/repos/databases, or write anything."""

    @abstractmethod
    def propose(self, *, context: dict[str, Any], state: dict[str, Any], allowed_capabilities: list[str], objective: str) -> ReasonerResponse: ...


class ReasoningFailure(Exception):
    def __init__(self, code: FailureCode, message: str):
        super().__init__(f"{code.value}: {message}")
        self.code = code


# ---------------------------------------------------------------------------
# Deterministic helpers (Core-owned; model cannot override)
# ---------------------------------------------------------------------------

def select_relevant_evidence(store: Any, *, audit_id: str, hypotheses: list[SecurityHypothesis], limit: int) -> list[Any]:
    """Relevance = hypothesis asset/category overlap, contradictions, recency.
    Deterministic; the model never chooses what it gets to see."""
    items = store.list(audit_id=audit_id)
    wanted_assets = {h.category for h in hypotheses}

    def score(it: Any) -> tuple[int, str]:
        s = 0
        prov = it.provenance if isinstance(it.provenance, dict) else {}
        labels = set(prov.get("labels", ()))
        if it.target_asset_id and any(it.target_asset_id in (h.supporting_evidence_ids + h.contradicting_evidence_ids) for h in hypotheses):
            s += 3
        if labels & {"rls-disabled", "secret-indicator", "vulnerable-dependency", "missing-authorization"}:
            s += 2
        if _wanted(wanted_assets, it):
            s += 1
        return (s, it.timestamp)

    ranked = sorted(items, key=score, reverse=True)
    return ranked[: max(1, limit)]


def _wanted(wanted: set[str], item: Any) -> bool:
    text = f"{item.content_summary} {item.location}".lower()
    return any(w.lower() in text for w in wanted if w)


def action_fingerprint(action: ReasonerAction) -> str:
    import hashlib as _hl

    params = "|".join(f"{k}={action.parameters.get(k)}" for k in sorted(action.parameters))
    return _hl.sha256(f"{action.kind.value}|{action.tool_id}|{action.target}|{params}".encode()).hexdigest()


# ---------------------------------------------------------------------------
# Reasoning engine (the loop)
# ---------------------------------------------------------------------------

class IterationRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    iteration: int
    input_context_digest: str = ""
    hypothesis_snapshot: tuple[str, ...] = ()
    action_proposal: str = ""
    policy_result: str = ""
    tool_invocation_id: str = ""
    resulting_evidence: tuple[str, ...] = ()
    state_transition: str = ""
    termination_reason: str = ""


class SessionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    session_id: str
    audit_id: str
    status: SessionStatus
    termination_reason: str = ""
    iterations: int = 0
    tool_calls: int = 0
    observation_ids: tuple[str, ...] = ()
    candidate_ids: tuple[str, ...] = ()
    hypothesis_ids: tuple[str, ...] = ()
    trail: tuple[IterationRecord, ...] = ()


class ReasoningEngine:
    """Owns the loop. `execute_tool` is an injected Core-validated callable
    (tests wire the real ToolExecutor; the engine itself never shells out)."""

    def __init__(
        self,
        *,
        session: ReasoningSession,
        provider: ReasonerProvider,
        registry: ToolRegistry,
        policy: StrictPolicyEngine,
        store: Any,
        execute_tool: Any | None = None,
        objective: str = "security review",
    ):
        if not isinstance(policy, StrictPolicyEngine):
            raise TypeError("reasoning requires StrictPolicyEngine")
        self._session = session
        self._provider = provider
        self._registry = registry
        self._policy = policy
        self._store = store
        self._execute_tool = execute_tool
        self._objective = objective[:500]
        self._hypotheses: dict[str, SecurityHypothesis] = {}
        self._trail: list[IterationRecord] = []
        self._seen_actions: dict[str, int] = {}
        self._start = time.monotonic()

    @property
    def session(self) -> ReasoningSession:
        return self._session

    @property
    def hypotheses(self) -> list[SecurityHypothesis]:
        return list(self._hypotheses.values())

    # -- validation (Core authority; model proposals are guilty until proven valid) --
    def validate_action(self, action: ReasonerAction) -> tuple[bool, str]:
        if action.kind == ActionKind.CONCLUDE:
            return True, "conclude"
        if action.kind == ActionKind.CORRELATE:
            return True, "correlate-analysis-only"
        if action.kind == ActionKind.REQUEST_VERIFICATION:
            if not action.reason:
                return False, "verification proposal needs a reason"
            return True, "verification-proposal-only"
        # defense in depth: even a smuggled payload (bypassing constructors)
        # is rejected here — raw shell fields can never become commands
        banned = {"command", "shell", "script", "cmd", "exec", "system", "eval"}
        if banned & {str(k).lower() for k in (action.parameters or {})}:
            return False, "raw-shell-denied"
        # privilege smuggling is rejected outright: the model may suggest
        # verification, but never set profile/permission/role fields
        priv = {"profile", "permission", "permissions", "role", "roles", "privilege", "privileges", "admin", "sudo", "escalate"}
        if priv & {str(k).lower() for k in (action.parameters or {})}:
            return False, "privilege-fields-denied"
        # tool-backed kinds require a registered tool + target + reason
        if not action.tool_id or not action.target or not action.reason:
            return False, "tool action needs tool_id+target+reason"
        try:
            spec = self._registry.get(action.tool_id)
        except ValueError:
            return False, "unknown-tool"
        target = action.target
        if target != target.strip() or not target or "\x00" in target:
            return False, "bad-target"
        if ".." in target.replace("\\", "/").split("/"):
            return False, "bad-target:traversal"
        if target.startswith("/") or (len(target) > 1 and target[1] == ":"):
            return False, "bad-target:absolute"
        return True, f"tool={spec.tool_id}"

    def _context_for_provider(self, hypotheses: list[SecurityHypothesis]) -> dict[str, Any]:
        from emo_cyber_agent.core.repository import redact_credentials

        relevant = select_relevant_evidence(self._store, audit_id=self._session.audit_id, hypotheses=hypotheses, limit=self._session.budget.max_evidence_context)
        return {
            "audit_id": self._session.audit_id,
            "evidence": [
                {"id": e.id, "tool": e.source_tool, "locator": e.location, "summary": redact_credentials(e.content_summary[:300]), "digest": e.content_hash, "timestamp": e.timestamp}
                for e in relevant
            ],
            "hypotheses": [{"id": h.hypothesis_id, "statement": h.statement[:300], "status": h.status.value, "confidence": h.confidence} for h in hypotheses],
            "iteration": self._session.iteration,
        }

    def _digest(self, obj: Any) -> str:
        import hashlib as _hl
        import json as _js

        return _hl.sha256(_js.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()

    def _check_budgets(self) -> str | None:
        b = self._session.budget
        if self._session.iteration >= b.max_iterations:
            return FailureCode.BUDGET_EXHAUSTED.value
        if self._session.tool_calls >= b.max_tool_calls:
            return FailureCode.BUDGET_EXHAUSTED.value
        if time.monotonic() - self._start >= b.max_wall_time_s:
            return FailureCode.BUDGET_EXHAUSTED.value
        if self._session.no_progress_streak >= b.no_progress_limit:
            return FailureCode.NO_PROGRESS.value
        return None

    def _record(self, **kw: Any) -> None:
        data: dict[str, Any] = {"iteration": self._session.iteration}
        data.update(kw)
        self._trail.append(IterationRecord(**data))

    def _apply_correlation(self) -> tuple[list[SecurityObservation], list[FindingCandidate]]:
        engine = CorrelationEngine(self._store)
        obs, cands, _ = engine.correlate(audit_id=self._session.audit_id)
        return obs, cands

    def _reassess(self, hyps: list[SecurityHypothesis], observations: list[SecurityObservation]) -> bool:
        """Update hypothesis support from fresh observations. Returns progress."""
        progressed = False
        for h in hyps:
            # deterministic confidence from graph-grounded counts
            sources = len({e for e in h.supporting_evidence_ids})
            new_supp = h.supporting_evidence_ids
            conf = compute_confidence(n_evidence=len(h.supporting_evidence_ids), n_sources=max(1, sources), has_conflict=bool(h.contradicting_evidence_ids))
            status = h.status
            if h.supporting_evidence_ids and status == HypothesisStatus.OPEN:
                status = HypothesisStatus.SUPPORTED
                progressed = True
            elif not h.supporting_evidence_ids and status == HypothesisStatus.OPEN:
                status = HypothesisStatus.NEEDS_EVIDENCE
                progressed = True
            if conf != h.confidence or status != h.status or new_supp != h.supporting_evidence_ids:
                progressed = True
            self._hypotheses[h.hypothesis_id] = SecurityHypothesis(**{**h.model_dump(), "confidence": conf, "status": status, "supporting_evidence_ids": new_supp, "updated_at": datetime.now(timezone.utc).isoformat()})
        return progressed

    def run(self) -> SessionResult:
        session = self._session.transition_to(SessionStatus.OBSERVING, reason="start")
        self._session = session
        all_obs: list[SecurityObservation] = []
        all_cands: list[FindingCandidate] = []
        retries = 0

        while True:
            over = self._check_budgets()
            if over == FailureCode.BUDGET_EXHAUSTED.value:
                session = self._session.transition_to(SessionStatus.BUDGET_EXHAUSTED, reason="budget exhausted")
                self._session = session
                self._record(state_transition=f"→{session.status.value}", termination_reason="budget exhausted")
                break
            if over == FailureCode.NO_PROGRESS.value:
                session = self._session.transition_to(SessionStatus.CONCLUDING, reason="no progress")
                self._session = session
                self._record(state_transition=f"→{session.status.value}", termination_reason="no progress")
                session = self._session.transition_to(SessionStatus.COMPLETED, reason="no progress: conclude without verdict")
                self._session = session
                break

            hyps = list(self._hypotheses.values())
            ctx = self._context_for_provider(hyps)
            if self._session.status != SessionStatus.OBSERVING:
                session = self._session.transition_to(SessionStatus.OBSERVING, reason="observe")
                self._session = session
            self._session = ReasoningSession(**{**self._session.model_dump(), "iteration": self._session.iteration + 1, "updated_at": datetime.now(timezone.utc).isoformat()})
            session = self._session.transition_to(SessionStatus.HYPOTHESIZING, reason="hypothesize")
            self._session = session
            try:
                response = self._provider.propose(context=ctx, state={"iteration": session.iteration, "status": session.status.value, "phase": session.phase.value}, allowed_capabilities=self._allowed_capabilities(), objective=self._objective)
            except Exception as e:
                session = self._session.transition_to(SessionStatus.FAILED, reason=f"model unavailable: {type(e).__name__}")
                self._session = session
                self._record(state_transition=f"→{session.status.value}", termination_reason="model unavailable")
                break
            if response.session_id != session.session_id:
                session = self._session.transition_to(SessionStatus.FAILED, reason="model invalid response: session mismatch")
                self._session = session
                self._record(state_transition=f"→{session.status.value}", termination_reason="session mismatch")
                break

            progressed = False
            # ingest hypothesis drafts (Core-owned objects; model text is DATA)
            for draft in response.hypotheses:
                refs = tuple(r for r in draft.evidence_refs if self._store.retrieve(r) is not None and self._owns(draft, r))
                h = SecurityHypothesis(audit_id=session.audit_id, category=draft.category[:60], statement=draft.statement[:500], supporting_evidence_ids=refs, status=HypothesisStatus.NEEDS_EVIDENCE if not refs else HypothesisStatus.OPEN)
                self._hypotheses[h.hypothesis_id] = h
                progressed = True
            session = self._session.transition_to(SessionStatus.PLANNING, reason="hypothesize")
            self._session = session

            if response.termination_request or not response.next_actions:
                session = self._session.transition_to(SessionStatus.CONCLUDING, reason="termination requested" if response.termination_request else "no actions")
                self._session = session
                self._record(state_transition=f"→{session.status.value}", termination_reason="provider concluded")
                session = self._session.transition_to(SessionStatus.COMPLETED, reason="concluded")
                self._session = session
                break

            action = response.next_actions[0]
            ok, why = self.validate_action(action)
            fp = action_fingerprint(action)
            self._seen_actions[fp] = self._seen_actions.get(fp, 0) + 1
            if self._seen_actions[fp] > session.budget.max_repeated_action_count:
                session = self._session.transition_to(SessionStatus.CONCLUDING, reason="loop detected")
                self._session = session
                self._record(action_proposal=fp[:12], state_transition=f"→{session.status.value}", termination_reason="loop detected")
                session = self._session.transition_to(SessionStatus.COMPLETED, reason="loop detected: conclude without verdict")
                self._session = session
                break
            if not ok:
                if retries < 1:
                    # bounded repair: re-ask the provider once before penalizing
                    retries += 1
                    self._record(action_proposal=fp[:12], policy_result=f"rejected:{why}", state_transition="retry-once")
                    continue
                session = self._session.transition_to(SessionStatus.REASSESSING, reason=f"action rejected: {why}")
                self._session = session
                self._record(action_proposal=fp[:12], policy_result=f"rejected:{why}", state_transition=f"→{session.status.value}")
                self._session = ReasoningSession(**{**self._session.model_dump(), "no_progress_streak": self._session.no_progress_streak + 1, "updated_at": datetime.now(timezone.utc).isoformat()})
                continue
            retries = 0

            if action.kind == ActionKind.CONCLUDE:
                session = self._session.transition_to(SessionStatus.CONCLUDING, reason="conclude action")
                self._session = session
                self._record(action_proposal=fp[:12], state_transition=f"→{session.status.value}")
                session = self._session.transition_to(SessionStatus.COMPLETED, reason="concluded by action")
                self._session = session
                progressed = True
                break
            if action.kind == ActionKind.CORRELATE:
                session = self._session.transition_to(SessionStatus.CORRELATING, reason="correlate")
                self._session = session
                obs, cands = self._apply_correlation()
                all_obs.extend(obs)
                all_cands.extend(cands)
                progressed = progressed or bool(obs or cands)
                self._record(action_proposal=fp[:12], state_transition=f"→{session.status.value}", resulting_evidence=tuple(o.id for o in obs[:5]))
                session = self._session.transition_to(SessionStatus.REASSESSING, reason="reassess")
                self._session = session
                progressed = self._reassess(list(self._hypotheses.values()), obs) or progressed
                self._session = ReasoningSession(**{**self._session.model_dump(), "no_progress_streak": 0 if progressed else self._session.no_progress_streak + 1, "updated_at": datetime.now(timezone.utc).isoformat()})
                continue
            if action.kind == ActionKind.REQUEST_VERIFICATION:
                # proposal ONLY — recorded, never executed here (ECA-T010 owns execution)
                session = self._session.transition_to(SessionStatus.REASSESSING, reason="verification proposed (not executed)")
                self._session = session
                self._record(action_proposal=fp[:12], policy_result="verification-proposal-recorded", state_transition=f"→{session.status.value}")
                progressed = True
                self._session = ReasoningSession(**{**self._session.model_dump(), "no_progress_streak": 0, "updated_at": datetime.now(timezone.utc).isoformat()})
                continue

            # tool-backed action: Core validation → strict policy → executor
            session = self._session.transition_to(SessionStatus.REQUESTING_ACTION, reason=why)
            self._session = session
            capability = self._capability_for(action)
            if capability is None:
                self._record(action_proposal=fp[:12], policy_result="rejected:unknown-capability", state_transition="reassess")
                session = self._session.transition_to(SessionStatus.REASSESSING, reason="unknown capability")
                self._session = session
                self._session = ReasoningSession(**{**self._session.model_dump(), "no_progress_streak": self._session.no_progress_streak + 1, "updated_at": datetime.now(timezone.utc).isoformat()})
                continue
            decision = self._policy.issue_decision(session.audit_id, action.tool_id, action.target, "read_only", [capability])
            if not decision.allowed:
                self._record(action_proposal=fp[:12], policy_result=f"denied:{','.join(decision.reason_codes)}", state_transition="reassess")
                session = self._session.transition_to(SessionStatus.REASSESSING, reason="policy denied")
                self._session = session
                self._session = ReasoningSession(**{**self._session.model_dump(), "no_progress_streak": self._session.no_progress_streak + 1, "updated_at": datetime.now(timezone.utc).isoformat()})
                continue
            if self._execute_tool is None:
                self._record(action_proposal=fp[:12], policy_result="allowed:no-executor", state_transition="reassess")
                session = self._session.transition_to(SessionStatus.REASSESSING, reason="no executor wired")
                self._session = session
                continue
            session = self._session.transition_to(SessionStatus.WAITING_FOR_RESULT, reason="executing")
            self._session = session
            try:
                new_items = self._execute_tool(action=action, invocation={"audit_id": session.audit_id, "capability": capability, "decision_id": decision.decision_id, "target": action.target})
            except Exception as e:
                self._record(action_proposal=fp[:12], policy_result="allowed", state_transition="tool-failed", termination_reason=f"{type(e).__name__}")
                session = self._session.transition_to(SessionStatus.REASSESSING, reason="tool failed")
                self._session = session
                self._session = ReasoningSession(**{**self._session.model_dump(), "no_progress_streak": self._session.no_progress_streak + 1, "updated_at": datetime.now(timezone.utc).isoformat()})
                continue
            eids: list[str] = []
            for item in new_items or []:
                try:
                    self._store.store(item, audit_id=session.audit_id)
                    eids.append(item.id)
                except ValueError:
                    continue
            self._session = ReasoningSession(**{**self._session.model_dump(), "tool_calls": self._session.tool_calls + 1, "action_ids": (*self._session.action_ids, action.action_id), "updated_at": datetime.now(timezone.utc).isoformat()})
            session = self._session.transition_to(SessionStatus.CORRELATING, reason="correlate results")
            self._session = session
            obs, cands = self._apply_correlation()
            all_obs.extend(obs)
            all_cands.extend(cands)
            self._record(action_proposal=fp[:12], policy_result=f"allowed:{decision.decision_id[:8]}", tool_invocation_id=decision.decision_id[:8], resulting_evidence=tuple(eids[:5]), state_transition=f"→{session.status.value}")
            session = self._session.transition_to(SessionStatus.REASSESSING, reason="reassess")
            self._session = session
            progressed = bool(eids) or bool(obs) or bool(cands)
            self._reassess(list(self._hypotheses.values()), obs)
            self._session = ReasoningSession(**{**self._session.model_dump(), "no_progress_streak": 0 if progressed else self._session.no_progress_streak + 1, "updated_at": datetime.now(timezone.utc).isoformat()})

        return SessionResult(
            session_id=self._session.session_id,
            audit_id=self._session.audit_id,
            status=self._session.status,
            termination_reason=self._session.termination_reason,
            iterations=self._session.iteration,
            tool_calls=self._session.tool_calls,
            observation_ids=tuple(o.id for o in all_obs),
            candidate_ids=tuple(c.candidate_id for c in all_cands),
            hypothesis_ids=tuple(self._hypotheses),
            trail=tuple(self._trail),
        )

    def _owns(self, draft: HypothesisDraft, ref: str) -> bool:
        item = self._store.retrieve(ref)
        if item is None:
            return False
        # cross-audit refs are dropped: evidence must live in THIS session's audit
        try:
            self._store.get(ref, audit_id=self._session.audit_id)
            return True
        except KeyError:
            return False

    def _allowed_capabilities(self) -> list[str]:
        return ["scanner.local.execute", "repository.read", "repository.list", "repository.search", "repository.metadata", "supabase.table.read", "supabase.policy.read", "supabase.grant.read", "supabase.view.read", "supabase.function.read", "supabase.schema.read", "supabase.project.read"]

    def _capability_for(self, action: ReasonerAction) -> str | None:
        try:
            spec = self._registry.get(action.tool_id)
        except ValueError:
            return None
        want = self._allowed_capabilities()
        for cap in spec.capabilities_required:
            if cap in want:
                return cap
        return None
