"""Bounded attack-path analysis — POST-RC-009.

Security-relevant paths over the existing code graph: actor →
entry → components → boundary crossings → target asset. A graph
path is NOT an executable exploit path. Classes: POSSIBLE_PATH
(structure only), SUPPORTED_PATH (evidence attached),
VERIFIED_PATH (verification evidence supplied by the caller —
never assigned here without it). No EXPLOIT_CONFIRMED exists.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from emo_cyber_agent.threat_modeling.errors import ThreatModelError, ThreatModelErrorCode
from emo_cyber_agent.threat_modeling.spec import AttackPath, assert_no_threat_verdicts


def find_attack_paths(
    code_graph: Any,
    *,
    audit_id: str,
    max_paths: int = 25,
    max_length: int = 8,
    verification_evidence: dict[str, tuple[str, ...]] | None = None,
) -> tuple[list[AttackPath], bool]:
    """BFS from entry handlers over call edges to database-linked code.

    Returns (paths, partial). partial=True when budgets stopped the walk.
    """
    verification_evidence = verification_evidence or {}
    snapshot = getattr(code_graph, "snapshot", None)
    project = getattr(snapshot, "project", None)
    if project is None or project.audit_id != audit_id:
        raise ThreatModelError(ThreatModelErrorCode.CROSS_AUDIT, "code graph bound to a different audit")
    endpoints = getattr(code_graph, "endpoints", {}) or {}
    call_edges: dict[str, set[str]] = {}
    for edge in getattr(code_graph, "call_edges", []) or []:
        call_edges.setdefault(edge.caller_id, set()).add(edge.callee_id)
    db_code: dict[str, str] = {}
    for rel in getattr(code_graph, "db_relations", []) or []:
        db_code.setdefault(rel.code_id, rel.database_object)
    boundaries = getattr(code_graph, "boundaries", {}) or {}
    handler_boundary: dict[str, str] = {}
    for bid, boundary in sorted(boundaries.items()):
        if boundary.protects_id:
            handler_boundary[boundary.protects_id] = bid
    paths: list[AttackPath] = []
    partial = False
    counter = 0
    for eid in sorted(endpoints):
        endpoint = endpoints[eid]
        if not endpoint.handler_id:
            continue
        entry_ref = f"entry-{eid}"
        frontier: deque[tuple[str, tuple[str, ...]]] = deque([(endpoint.handler_id, (endpoint.handler_id,))])
        visited: set[str] = set()
        while frontier and len(paths) < max_paths:
            current, trail = frontier.popleft()
            if len(trail) > max(2, max_length):
                partial = True
                continue
            if current in db_code:
                counter += 1
                pid = f"attack-path-{counter:03d}"
                crossings = sorted({handler_boundary[n] for n in trail if n in handler_boundary})
                evidence = tuple(verification_evidence.get(pid, ()))
                path_class = "VERIFIED_PATH" if evidence else ("SUPPORTED_PATH" if crossings else "POSSIBLE_PATH")
                assert_no_threat_verdicts(pid, eid)
                paths.append(AttackPath(
                    path_id=pid, actor_id="actor-external-user", entry_id=entry_ref,
                    nodes=tuple(trail), boundary_crossings=tuple(crossings),
                    target_asset_id=db_code[current], path_class=path_class, evidence_ids=evidence,
                    limitations=("graph path only: not an executable exploit path",) if not evidence else ("verification evidence attached by caller",),
                ))
                continue
            if current in visited:
                continue
            visited.add(current)
            for nxt in sorted(call_edges.get(current, ())):
                if nxt not in trail:
                    frontier.append((nxt, trail + (nxt,)))
                if len(paths) >= max_paths:
                    partial = True
                    break
        if len(paths) >= max_paths:
            partial = True
            break
    return paths, partial
