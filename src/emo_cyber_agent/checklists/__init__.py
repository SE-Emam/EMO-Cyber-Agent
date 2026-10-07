"""Security review checklists — POST-T020.

Review guidance as pure DATA. This package never executes checks, never
probes systems, and grants nothing: no capabilities, no policy
decisions, no severity verdicts. A checklist names WHAT to review, WHAT
evidence to cite, HOW to verify, and WHAT observable condition counts
as satisfied. All judgment stays with the human reviewer.

Shape mirrors ``subagent.bootstrap`` (frozen pydantic models,
``to_dict`` / ``from_dict`` / ``to_canonical_json``, deterministic
tuple outputs, kebab-case ids, semver versions) without duplicating its
host-readiness domain.
"""

from emo_cyber_agent.checklists.catalog import (
    OFFICIAL_CHECKLIST_IDS,
    get_by_scope,
    get_checklist,
    list_checklists,
)
from emo_cyber_agent.checklists.spec import Checklist, ChecklistItem

__all__ = [
    "OFFICIAL_CHECKLIST_IDS",
    "Checklist",
    "ChecklistItem",
    "get_by_scope",
    "get_checklist",
    "list_checklists",
]
