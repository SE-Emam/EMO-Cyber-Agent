"""Security Playbook System — POST-RC-004.

Playbook coordinates. Task defines WHAT. Skill defines HOW. Tool
provides FACTS. Policy defines AUTHORITY. This package MUST NEVER
become a second Core.
"""

from emo_cyber_agent.playbooks.registry import PlaybookRegistry
from emo_cyber_agent.playbooks.resolver import PlaybookResolver, evaluate_condition
from emo_cyber_agent.playbooks.service import PlaybookService
from emo_cyber_agent.playbooks.spec import (
    PlaybookError,
    PlaybookErrorCode,
    PlaybookSpec,
    PlaybookStatus,
    PlaybookTrust,
    ProjectContext,
    ResolvedPlaybook,
    ResolutionStatus,
)
from emo_cyber_agent.playbooks.validator import PlaybookValidator

__all__ = [
    "PlaybookError",
    "PlaybookErrorCode",
    "PlaybookRegistry",
    "PlaybookResolver",
    "PlaybookService",
    "PlaybookSpec",
    "PlaybookStatus",
    "PlaybookTrust",
    "PlaybookValidator",
    "ProjectContext",
    "ResolvedPlaybook",
    "ResolutionStatus",
    "evaluate_condition",
]
