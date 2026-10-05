"""Change service — POST-RC-008.

Core-owned orchestration: compare → predicates → propagate →
impact → evidence → plan → report view. Read-only, deterministic,
planning-only. No git client, no child processes, no model, no findings.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.change_analysis.diff import compare_snapshots
from emo_cyber_agent.change_analysis.errors import ChangeError, ChangeErrorCode
from emo_cyber_agent.change_analysis.impact import analyze_impact, propagate
from emo_cyber_agent.change_analysis.planner import plan_review
from emo_cyber_agent.change_analysis.predicates import evaluate_predicates
from emo_cyber_agent.change_analysis.provenance import build_change_provenance
from emo_cyber_agent.change_analysis.spec import (
    BaselineSecurityObservation,
    ChangeReportView,
    ChangeReviewPlan,
    ChangeSet,
    ComparisonSnapshot,
    SecurityImpact,
    VerificationHandoff,
    assert_no_verdicts,
    canonical_digest,
)


class ChangeService:
    """Single entry point for change-aware review. Hosts call this;
    nothing here shells out, schedules, or remediates."""

    def __init__(self, *, skill_registry: Any = None, pack_registry: Any = None, max_hops: int = 4, max_nodes: int = 500):
        self._skills = skill_registry
        self._packs = pack_registry
        self._max_hops = max_hops
        self._max_nodes = max_nodes

    def review(
        self,
        base: ComparisonSnapshot,
        target: ComparisonSnapshot,
        *,
        base_graph: Any = None,
        target_graph: Any = None,
        review_mode: str = "TARGETED_REVIEW",
        expected_base_revision: str = "",
        expected_target_revision: str = "",
    ) -> tuple[ChangeSet, dict[str, list[str]], SecurityImpact, ChangeReviewPlan, list[Any]]:
        for name, graph in (("base", base_graph), ("target", target_graph)):
            if graph is not None:
                snapshot = getattr(graph, "snapshot", None)
                project = getattr(snapshot, "project", None)
                if project is None or project.audit_id != base.audit_id:
                    raise ChangeError(ChangeErrorCode.CROSS_AUDIT, f"{name} graph bound to a different audit")
        if expected_base_revision and base.revision != expected_base_revision:
            raise ChangeError(ChangeErrorCode.STALE_SNAPSHOT, "base snapshot is stale")
        if expected_target_revision and target.revision != expected_target_revision:
            raise ChangeError(ChangeErrorCode.STALE_SNAPSHOT, "target snapshot is stale")
        changeset = compare_snapshots(base, target, base_graph=base_graph, target_graph=target_graph)
        predicates = evaluate_predicates(changeset, base_graph=base_graph, target_graph=target_graph)
        surface, partial, _trail = propagate(changeset, target_graph=target_graph, max_hops=self._max_hops, max_nodes=self._max_nodes)
        impact = analyze_impact(changeset, predicates, surface, propagation_partial=partial, skill_registry=self._skills)
        evidence = self.build_evidence(changeset, impact, predicates)
        impact = impact.model_copy(update={"evidence_ids": tuple(e.id for e in evidence)})
        plan = plan_review(changeset, impact, predicates, review_mode=review_mode, pack_registry=self._packs)
        return changeset, predicates, impact, plan, evidence

    def build_evidence(self, changeset: ChangeSet, impact: SecurityImpact, predicates: dict[str, list[str]]) -> list[Any]:
        """One EvidenceItem per changed file + one impact record. Diff
        text and commit metadata stay digests/previews: untrusted DATA,
        redacted, never instructions."""
        from emo_cyber_agent.core.repository import redact_credentials
        from emo_cyber_agent.domain.models import EvidenceItem

        items: list[Any] = []
        for changed in changeset.files:
            summary = redact_credentials(f"change {changed.state} {changed.path} classifications={','.join(changed.classifications) or 'none'}")[:400]
            assert_no_verdicts(summary)
            items.append(EvidenceItem(
                source_tool="change-analysis", source_version="1.0", target_asset_id=changeset.project_id or None,
                location=f"{changed.path}", content_summary=summary,
                content_hash=canonical_digest({"summary": summary}),
                provenance=build_change_provenance(
                    audit_id=changeset.audit_id, project_id=changeset.project_id,
                    base_snapshot_id=changeset.base_snapshot_id, target_snapshot_id=changeset.target_snapshot_id,
                    changed_object=f"file:{changed.path}", change_digest=changeset.change_digest, coverage=changeset.coverage,
                ),
            ))
        impact_summary = redact_credentials(f"impact affected={impact.affected} domains={','.join(impact.domains) or 'none'} predicates={','.join(sorted(predicates)) or 'none'} coverage={impact.coverage}")[:400]
        assert_no_verdicts(impact_summary)
        items.append(EvidenceItem(
            source_tool="change-analysis", source_version="1.0", target_asset_id=changeset.project_id or None,
            location=f"snapshot:{changeset.target_snapshot_id}", content_summary=impact_summary,
            content_hash=canonical_digest({"summary": impact_summary}),
            provenance=build_change_provenance(
                audit_id=changeset.audit_id, project_id=changeset.project_id,
                base_snapshot_id=changeset.base_snapshot_id, target_snapshot_id=changeset.target_snapshot_id,
                changed_object="security-impact", change_digest=changeset.change_digest, coverage=impact.coverage,
            ),
        ))
        return items

    def check_handoff(self, handoff: VerificationHandoff, *, current_snapshot_id: str) -> None:
        """Stale verification results are never reused: the handoff is
        valid only for its target snapshot (or an explicitly listed
        compatible one)."""
        if current_snapshot_id != handoff.target_snapshot_id and current_snapshot_id not in handoff.compatible_snapshots:
            raise ChangeError(ChangeErrorCode.VERIFICATION_STALE, f"handoff {handoff.handoff_id} not compatible with snapshot {current_snapshot_id}")

    def report_view(self, changeset: ChangeSet, impact: SecurityImpact, plan: ChangeReviewPlan, evidence_ids: tuple[str, ...] = ()) -> ChangeReportView:
        return ChangeReportView(
            base_revision=changeset.base_revision, target_revision=changeset.target_revision,
            changed_files=tuple(sorted({f.path for f in changeset.files})),
            affected_domains=tuple(impact.domains), review_mode=plan.review_mode, coverage=impact.coverage,
            limitations=tuple(plan.limitations),
            targeted_checks=tuple(sorted({*plan.targeted_skills, *plan.targeted_packs, *plan.targeted_tasks})),
            evidence_references=tuple(evidence_ids),
            verification_handoffs=tuple(h.handoff_id for h in plan.verification_handoffs),
        )


def compare_baselines(before: dict[str, str], after: dict[str, str]) -> list[BaselineSecurityObservation]:
    """Compare observation digests before vs after. Presence states
    only — never Finding lifecycle states."""
    observations: list[BaselineSecurityObservation] = []
    for key in sorted(set(before) | set(after)):
        if key not in before:
            state = "NEW"
        elif key not in after:
            state = "REMOVED"
        elif before[key] == after[key]:
            state = "PERSISTING"
        elif before[key] and after[key]:
            state = "CHANGED"
        else:
            state = "INDETERMINATE"
        observations.append(BaselineSecurityObservation(observation_key=key, state=state, before_digest=before.get(key, ""), after_digest=after.get(key, "")))
    return observations
