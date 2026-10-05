"""Change analysis — POST-RC-008.

Facts about change, not verdicts. Previous Snapshot → Change Set →
Security Impact → Targeted Re-analysis plan → Evidence → Correlation
→ Verification handoff. No scheduler, no daemon, no remediation.
"""

from emo_cyber_agent.change_analysis.diff import compare_snapshots
from emo_cyber_agent.change_analysis.errors import ChangeError, ChangeErrorCode
from emo_cyber_agent.change_analysis.impact import analyze_impact, propagate
from emo_cyber_agent.change_analysis.planner import plan_review
from emo_cyber_agent.change_analysis.predicates import evaluate_predicates
from emo_cyber_agent.change_analysis.provenance import build_change_provenance
from emo_cyber_agent.change_analysis.service import ChangeService, compare_baselines
from emo_cyber_agent.change_analysis.spec import (
    BASELINE_STATES,
    CHANGE_CLASSIFICATIONS,
    CHANGE_CONTRACT_VERSION,
    CHANGE_PREDICATES,
    FILE_CHANGE_STATES,
    REVIEW_MODES,
    AffectedSurface,
    BaselineSecurityObservation,
    ChangeClassification,
    ChangeReportView,
    ChangeReviewPlan,
    ChangeSet,
    ChangedDatabaseRelation,
    ChangedDependency,
    ChangedFile,
    ChangedRegion,
    ChangedRoute,
    ChangedSymbol,
    ComparisonSnapshot,
    SecurityImpact,
    VerificationHandoff,
    assert_no_verdicts,
    canonical_digest,
)

__all__ = [
    "BASELINE_STATES",
    "CHANGE_CLASSIFICATIONS",
    "CHANGE_CONTRACT_VERSION",
    "CHANGE_PREDICATES",
    "FILE_CHANGE_STATES",
    "REVIEW_MODES",
    "AffectedSurface",
    "BaselineSecurityObservation",
    "ChangeClassification",
    "ChangeError",
    "ChangeErrorCode",
    "ChangeReportView",
    "ChangeReviewPlan",
    "ChangeService",
    "ChangeSet",
    "ChangedDatabaseRelation",
    "ChangedDependency",
    "ChangedFile",
    "ChangedRegion",
    "ChangedRoute",
    "ChangedSymbol",
    "ComparisonSnapshot",
    "SecurityImpact",
    "VerificationHandoff",
    "analyze_impact",
    "assert_no_verdicts",
    "canonical_digest",
    "compare_baselines",
    "compare_snapshots",
    "evaluate_predicates",
    "plan_review",
    "propagate",
    "build_change_provenance",
]
