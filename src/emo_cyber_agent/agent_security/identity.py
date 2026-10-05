"""Identity helpers — POST-RC-010.

Identity records describe; they never authenticate. Actual
verification stays downstream and provider-specific.
"""

from __future__ import annotations

from typing import Any


def identity_kind(declared: str) -> str:
    from emo_cyber_agent.agent_security.spec import IDENTITY_KINDS

    return declared if declared in IDENTITY_KINDS else "unknown"


def delegation_scope_covers(parent_scope: tuple[str, ...], child_scope: tuple[str, ...]) -> bool:
    """True iff every child scope element is within the parent scope.
    Pure set logic over declared strings; grants nothing."""
    return set(child_scope) <= set(parent_scope)


def widened_scopes(parent_scope: tuple[str, ...], child_scope: tuple[str, ...]) -> list[str]:
    return sorted(set(child_scope) - set(parent_scope))


def identity_chain(identities: Any, start_id: str, *, max_hops: int = 8) -> list[str]:
    """Follow delegation links deterministically for display only."""
    by_subject: dict[str, list[Any]] = {}
    delegations = getattr(identities, "delegations", None)
    items = delegations if isinstance(delegations, (list, tuple)) else (identities if isinstance(identities, (list, tuple)) else [])
    for delegation in items:
        by_subject.setdefault(getattr(delegation, "subject", ""), []).append(delegation)
    chain = [start_id]
    current = start_id
    for _ in range(max(1, max_hops)):
        links = sorted(by_subject.get(current, []), key=lambda d: getattr(d, "delegation_id", ""))
        if not links:
            break
        current = getattr(links[0], "delegate", "")
        if not current or current in chain:
            break
        chain.append(current)
    return chain
