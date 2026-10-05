"""Extension resolver — POST-RC-014.

Resolution is deterministic and explicit. The rules:

* an explicit pinned constraint resolves exactly, or fails;
* a range constraint resolves to the highest compatible version only
  when the host policy allows ``HIGHEST_COMPATIBLE``;
* without a constraint and without a configured policy there is no
  "latest" answer — the request is reported as ``VERSION_AMBIGUOUS``;
* two providers of the same token produce ``PROVIDER_CONFLICT`` and no
  winner, ever, because install order must not decide security behavior;
* dependency cycles, missing and incompatible dependencies are refused
  before anything could be loaded.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.extensions.compatibility import satisfies
from emo_cyber_agent.extensions.conflicts import ExtensionConflict, detect_cycles
from emo_cyber_agent.extensions.spec import (
    TRUSTED_STATES,
    ExtensionConflictKind,
    VersionPolicy,
    version_key,
)

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from emo_cyber_agent.extensions.registry import ExtensionRegistry

__all__ = [
    "ExtensionResolver",
    "Resolution",
    "ResolutionRequest",
]

_MAX_DEPTH = 10


class ResolutionRequest(BaseModel):
    """A read-only request: pick an extension by id or by provider token."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    extension_id: str = Field(default="", max_length=80)
    version_constraint: str = Field(default="", max_length=120)
    provide: str = Field(default="", max_length=120)
    policy: VersionPolicy = VersionPolicy.EXACT
    include_optional: bool = False

    def describe(self) -> str:
        if self.provide and not self.extension_id:
            return f"provide:{self.provide}"
        constraint = self.version_constraint or "*"
        return f"{self.extension_id}@{constraint}"


class Resolution(BaseModel):
    """Frozen resolution outcome with every alternative recorded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request: ResolutionRequest
    resolved: bool = False
    eligible: bool = False
    chosen: str = ""
    trust: str = ""
    alternatives: tuple[str, ...] = Field(default_factory=tuple)
    dependencies: tuple[str, ...] = Field(default_factory=tuple)
    conflicts: tuple[ExtensionConflict, ...] = Field(default_factory=tuple)
    notes: tuple[str, ...] = Field(default_factory=tuple)


class ExtensionResolver:
    """Deterministic resolver over a registry. Stateless per call."""

    def __init__(self, registry: ExtensionRegistry, *, policy: VersionPolicy | None = None) -> None:
        self._registry = registry
        self._policy = policy

    def resolve(self, request: ResolutionRequest) -> Resolution:
        policy = request.policy if self._policy is None else self._policy
        if request.provide and not request.extension_id:
            return self.resolve_provides(request.provide, policy=policy, request=request)
        if not request.extension_id:
            return Resolution(
                request=request,
                conflicts=(
                    ExtensionConflict(
                        kind=ExtensionConflictKind.DEPENDENCY_MISSING,
                        subject="",
                        note="empty resolution request",
                    ),
                ),
                notes=("request-empty",),
            )

        conflicts: list[ExtensionConflict] = []
        notes: list[str] = []
        alternatives = tuple(self._registry.versions(request.extension_id))

        chosen = self._choose(
            request.extension_id,
            request.version_constraint,
            policy,
            alternatives,
            conflicts,
            notes,
        )
        if not chosen:
            return Resolution(request=request, alternatives=alternatives, conflicts=tuple(conflicts), notes=tuple(notes))

        entry = self._registry.get(request.extension_id, chosen)
        identity = entry.identity
        dependencies, dep_conflicts, dep_notes = self._walk(entry, policy, request, set())
        conflicts.extend(dep_conflicts)
        notes.extend(dep_notes)

        eligible = entry.trust.state.value in TRUSTED_STATES
        if not eligible:
            notes.append(f"trust-not-loadable:{entry.trust.state.value}")
        if entry.lifecycle.value in ("quarantined", "rejected"):
            notes.append(f"lifecycle-not-loadable:{entry.lifecycle.value}")
            eligible = False

        return Resolution(
            request=request,
            resolved=not conflicts,
            eligible=eligible and not conflicts,
            chosen=identity,
            trust=entry.trust.state.value,
            alternatives=alternatives,
            dependencies=tuple(dependencies),
            conflicts=tuple(conflicts),
            notes=tuple(dict.fromkeys(notes)),
        )

    def resolve_provides(
        self,
        token: str,
        *,
        policy: VersionPolicy = VersionPolicy.EXACT,
        request: ResolutionRequest | None = None,
    ) -> Resolution:
        """Resolve a provider token. Conflicts stay conflicts."""
        base = request or ResolutionRequest(provide=token, policy=policy)
        providers = self._registry.provides_index().get(token, ())
        if not providers:
            return Resolution(
                request=base,
                conflicts=(
                    ExtensionConflict(
                        kind=ExtensionConflictKind.DEPENDENCY_MISSING,
                        subject=token,
                        note="no extension provides this token",
                    ),
                ),
                notes=("provider-absent",),
            )
        if len(providers) > 1:
            return Resolution(
                request=base,
                alternatives=providers,
                conflicts=(
                    ExtensionConflict(
                        kind=ExtensionConflictKind.PROVIDER_CONFLICT,
                        subject=token,
                        candidates=providers,
                        note="multiple providers; explicit host selection required",
                    ),
                ),
                notes=("provider-conflict",),
            )
        identity = providers[0]
        extension_id, version = identity.split("@", 1)
        inner = ResolutionRequest(extension_id=extension_id, version_constraint=f"=={version}", policy=VersionPolicy.EXACT)
        result = self.resolve(inner)
        return result.model_copy(
            update={
                "request": base,
                "notes": tuple(dict.fromkeys((*result.notes, f"provider-token:{token}"))),
            }
        )

    # -- internals --------------------------------------------------------

    def _choose(
        self,
        extension_id: str,
        constraint: str,
        policy: VersionPolicy,
        alternatives: tuple[str, ...],
        conflicts: list[ExtensionConflict],
        notes: list[str],
    ) -> str:
        if not alternatives:
            conflicts.append(
                ExtensionConflict(
                    kind=ExtensionConflictKind.DEPENDENCY_MISSING,
                    subject=f"{extension_id}@{constraint or '*'}",
                    note="extension not registered",
                )
            )
            notes.append("candidate-absent")
            return ""

        text = (constraint or "").strip()
        candidates = tuple(version for version in alternatives if satisfies(version, text or "*"))
        if not candidates:
            conflicts.append(
                ExtensionConflict(
                    kind=ExtensionConflictKind.DEPENDENCY_INCOMPATIBLE,
                    subject=f"{extension_id}@{text}",
                    candidates=alternatives,
                    note="no registered version satisfies the constraint",
                )
            )
            notes.append("candidate-incompatible")
            return ""

        if len(candidates) == 1:
            return candidates[0]

        pinned = text in candidates or any(text == f"=={candidate}" for candidate in candidates)
        if pinned and candidates:
            return sorted(candidates, key=version_key)[0]

        if policy is VersionPolicy.HIGHEST_COMPATIBLE:
            notes.append("policy:highest-compatible")
            return sorted(candidates, key=version_key)[-1]

        conflicts.append(
            ExtensionConflict(
                kind=ExtensionConflictKind.VERSION_AMBIGUOUS,
                subject=f"{extension_id}@{text or '*'}",
                candidates=candidates,
                note="multiple compatible versions; no latest-unspecified resolution",
            )
        )
        notes.append("policy:exact")
        return ""

    def _walk(
        self,
        entry: Any,
        policy: VersionPolicy,
        request: ResolutionRequest,
        seen: set[str],
        depth: int = 0,
    ) -> tuple[list[str], list[ExtensionConflict], list[str]]:
        identities: list[str] = []
        conflicts: list[ExtensionConflict] = []
        notes: list[str] = []
        if depth >= _MAX_DEPTH:
            conflicts.append(
                ExtensionConflict(
                    kind=ExtensionConflictKind.DEPENDENCY_CYCLE,
                    subject=entry.identity,
                    note="dependency depth limit reached",
                )
            )
            return identities, conflicts, notes

        graph: dict[str, tuple[str, ...]] = {}
        pending = [(entry, depth)]
        visited: set[str] = set()
        while pending:
            current, current_depth = pending.pop(0)
            if current.identity in visited:
                continue
            visited.add(current.identity)
            graph[current.extension_id] = tuple(dep.extension_id for dep in current.manifest.dependencies)
            for dependency in current.manifest.dependencies:
                sub_alternatives = tuple(self._registry.versions(dependency.extension_id))
                sub_conflicts: list[ExtensionConflict] = []
                sub_notes: list[str] = []
                chosen = self._choose(
                    dependency.extension_id,
                    dependency.version_constraint,
                    policy,
                    sub_alternatives,
                    sub_conflicts,
                    sub_notes,
                )
                conflicts.extend(sub_conflicts)
                notes.extend(sub_notes)
                if not chosen:
                    continue
                dep_entry = self._registry.get(dependency.extension_id, chosen)
                identities.append(dep_entry.identity)
                if dep_entry.trust.state.value not in TRUSTED_STATES:
                    notes.append(f"dependency-trust:{dep_entry.identity}={dep_entry.trust.state.value}")
                pending.append((dep_entry, current_depth + 1))
            if request.include_optional:
                for optional in current.manifest.optional_dependencies:
                    if optional.extension_id in self._registry.versions(optional.extension_id):
                        identities.append(f"{optional.extension_id}@optional")
                        notes.append(f"optional-included:{optional.extension_id}")

        for cycle in detect_cycles(graph):
            conflicts.append(
                ExtensionConflict(
                    kind=ExtensionConflictKind.DEPENDENCY_CYCLE,
                    subject=" -> ".join(cycle),
                    candidates=cycle,
                    note="dependency cycle refused before load",
                )
            )
        return identities, conflicts, notes
