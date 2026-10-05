"""Extension conflicts — POST-RC-014.

Conflicts are *detected and reported*, never resolved by luck. Install
order, discovery order and filesystem order must never decide which
extension wins, so every function here is order-independent: results are
sorted, cycles are reported as tuples of ids, and a provider conflict is
returned as ``PROVIDER_CONFLICT`` for the host to resolve explicitly.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.extensions.spec import ExtensionConflictKind

__all__ = [
    "ExtensionConflict",
    "detect_duplicates",
    "detect_cycles",
    "provider_conflicts",
    "require_single_provider",
]


class ExtensionConflict(BaseModel):
    """A deterministic, machine-readable conflict record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ExtensionConflictKind
    subject: str = Field(..., min_length=1, max_length=200)
    candidates: tuple[str, ...] = Field(default_factory=tuple)
    note: str = Field(default="", max_length=300)


def detect_duplicates(identities: Iterable[str]) -> tuple[ExtensionConflict, ...]:
    """Same ``id@version`` arriving from more than one source.

    Duplicates are a conflict even when the payloads are identical: the
    registry must never depend on which source was seen first."""
    seen: dict[str, int] = {}
    for identity in identities:
        seen[identity] = seen.get(identity, 0) + 1
    return tuple(
        ExtensionConflict(
            kind=ExtensionConflictKind.DUPLICATE_IDENTITY,
            subject=identity,
            candidates=(identity,),
            note=f"identity discovered {count} times",
        )
        for identity, count in sorted(seen.items())
        if count > 1
    )


def detect_cycles(edges: Mapping[str, Sequence[str]]) -> tuple[tuple[str, ...], ...]:
    """Deterministic cycle detection over an extension dependency graph.

    A cycle is refused *before* loading: ``A -> B -> A`` can never reach
    the registry's loadable state."""
    graph = {node: tuple(sorted(set(targets))) for node, targets in edges.items()}
    cycles: set[tuple[str, ...]] = set()
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for target in graph.get(node, ()):
            if target not in graph:
                continue
            marker = state.get(target, 0)
            if marker == 1:
                start = stack.index(target)
                cycle = tuple(stack[start:])
                if cycle:
                    rotated = min(cycle[i:] + cycle[:i] for i in range(len(cycle)))
                    cycles.add(rotated)
            elif marker == 0:
                visit(target)
        stack.pop()
        state[node] = 2

    for node in sorted(graph):
        if state.get(node, 0) == 0:
            visit(node)
    return tuple(sorted(cycles))


def provider_conflicts(providers: Mapping[str, Sequence[str]]) -> tuple[ExtensionConflict, ...]:
    """Two extensions providing the same token (e.g. ``verification-adapter:http``).

    No arbitrary winner: callers get a conflict and must select an
    explicit version/host configuration instead."""
    conflicts: list[ExtensionConflict] = []
    for token, candidates in sorted(providers.items()):
        unique = tuple(sorted(set(candidates)))
        if len(unique) > 1:
            conflicts.append(
                ExtensionConflict(
                    kind=ExtensionConflictKind.PROVIDER_CONFLICT,
                    subject=token,
                    candidates=unique,
                    note="multiple providers; explicit host selection required",
                )
            )
    return tuple(conflicts)


def require_single_provider(providers: Mapping[str, Sequence[str]]) -> tuple[ExtensionConflict, ...]:
    """Alias kept for call sites that read as a guard, not a query."""
    return provider_conflicts(providers)
