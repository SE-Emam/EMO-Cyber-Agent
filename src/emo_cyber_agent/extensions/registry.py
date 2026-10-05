"""Extension registry — POST-RC-014.

The registry is a version-keyed, deterministic, read-mostly store. It
registers *descriptions*: manifests, trust evaluations, lifecycle state
and health. It never executes an extension, never imports a module and
never decides a security verdict — resolvable state comes from the trust
process, and lifecycle transitions are host-side only (an extension
cannot move itself from ``discovered`` to ``loaded``).

There is no module-level singleton: every registry is constructed and
injected, so two audits can never observe each other's extensions.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.extensions.compatibility import CompatibilityResult, HostProfile, check_compatibility
from emo_cyber_agent.extensions.conflicts import provider_conflicts
from emo_cyber_agent.extensions.errors import ExtensionError, ExtensionErrorCode
from emo_cyber_agent.extensions.resolver import ExtensionResolver, Resolution, ResolutionRequest
from emo_cyber_agent.extensions.spec import (
    ALLOWED_TRANSITIONS,
    ExtensionHealth,
    ExtensionHealthStatus,
    ExtensionLifecycle,
    ExtensionManifest,
    ExtensionProvenance,
    ExtensionTrust,
    ExtensionTrustState,
    ExtensionType,
)
from emo_cyber_agent.extensions.trust import trust_allows_registration
from emo_cyber_agent.extensions.validator import ExtensionValidation, ExtensionValidator

__all__ = [
    "ALLOWED_QUERIES",
    "ExtensionRegistry",
    "RegisteredExtension",
    "RegistrySummary",
]

#: The complete read-only query surface. No raw import path, no execute.
ALLOWED_QUERIES: frozenset[str] = frozenset(
    {
        "check_compatibility",
        "get_extension",
        "get_health",
        "get_provenance",
        "list_by_type",
        "list_extensions",
        "resolve_extension",
    }
)


class RegisteredExtension(BaseModel):
    """One registered manifest plus its host-side evaluation state."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest: ExtensionManifest
    trust: ExtensionTrust
    lifecycle: ExtensionLifecycle = ExtensionLifecycle.REGISTERED
    health: ExtensionHealth = Field(default_factory=ExtensionHealth)
    origin: str = Field(default="", max_length=300)

    @property
    def extension_id(self) -> str:
        return self.manifest.extension_id

    @property
    def version(self) -> str:
        return self.manifest.version

    @property
    def identity(self) -> str:
        return f"{self.extension_id}@{self.version}"

    @property
    def extension_type(self) -> str:
        return self.manifest.type_value

    def summary(self) -> dict[str, Any]:
        """Read-only projection. Never exposes an entry point target."""
        return {
            "extension_id": self.extension_id,
            "version": self.version,
            "name": self.manifest.name,
            "extension_type": self.extension_type,
            "trust": self.trust.state.value,
            "source_class": self.trust.source_class.value,
            "lifecycle": self.lifecycle.value,
            "health": self.health.status.value,
            "digest": self.manifest.digest,
            "origin": self.origin,
        }


class RegistrySummary(BaseModel):
    """Aggregate view returned by list queries."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    count: int = 0
    entries: tuple[dict[str, Any], ...] = Field(default_factory=tuple)


class ExtensionRegistry:
    """Version-aware deterministic registry. No global state."""

    def __init__(self, *, validator: ExtensionValidator | None = None, host: HostProfile | None = None) -> None:
        self._entries: dict[tuple[str, str], RegisteredExtension] = {}
        self._validator = validator or ExtensionValidator()
        self._host = host

    # -- registration -----------------------------------------------------

    def register(
        self,
        manifest: ExtensionManifest,
        *,
        trust: ExtensionTrust,
        origin: str = "",
        lifecycle: ExtensionLifecycle | None = None,
        health: ExtensionHealth | None = None,
    ) -> RegisteredExtension:
        """Register a manifest. Rejected content is refused outright."""
        if not trust_allows_registration(trust):
            raise ExtensionError(
                ExtensionErrorCode.REJECTED,
                f"rejected extension cannot be registered: {manifest.extension_id}@{manifest.version}",
            )
        key = (manifest.extension_id, manifest.version)
        if key in self._entries:
            raise ExtensionError(
                ExtensionErrorCode.DUPLICATE,
                f"duplicate extension identity: {manifest.extension_id}@{manifest.version}",
            )
        resolved_lifecycle = lifecycle or (
            ExtensionLifecycle.QUARANTINED
            if trust.state is ExtensionTrustState.QUARANTINED
            else ExtensionLifecycle.REGISTERED
        )
        entry = RegisteredExtension(
            manifest=manifest,
            trust=trust,
            lifecycle=resolved_lifecycle,
            health=health or ExtensionHealth(),
            origin=origin,
        )
        self._entries[key] = entry
        return entry

    def unregister(self, extension_id: str, version: str) -> None:
        key = (extension_id, version)
        if key not in self._entries:
            raise ExtensionError(ExtensionErrorCode.NOT_FOUND, f"unknown extension: {extension_id}@{version}")
        del self._entries[key]

    # -- reads ------------------------------------------------------------

    def get(self, extension_id: str, version: str | None = None) -> RegisteredExtension:
        if version is not None:
            entry = self._entries.get((extension_id, version))
            if entry is None:
                raise ExtensionError(ExtensionErrorCode.NOT_FOUND, f"unknown extension: {extension_id}@{version}")
            return entry
        candidates = self.versions(extension_id)
        if not candidates:
            raise ExtensionError(ExtensionErrorCode.NOT_FOUND, f"unknown extension: {extension_id}")
        if len(candidates) > 1:
            raise ExtensionError(
                ExtensionErrorCode.VERSION_AMBIGUOUS,
                f"{extension_id} has {len(candidates)} versions: {', '.join(candidates)}",
            )
        return self._entries[(extension_id, candidates[0])]

    def list(self) -> list[RegisteredExtension]:
        return [self._entries[key] for key in sorted(self._entries)]

    def versions(self, extension_id: str) -> list[str]:
        from emo_cyber_agent.extensions.spec import version_key

        found = [key[1] for key in self._entries if key[0] == extension_id]
        return sorted(found, key=version_key)

    def list_by_type(self, extension_type: str | ExtensionType) -> list[RegisteredExtension]:
        wanted = extension_type.value if isinstance(extension_type, ExtensionType) else str(extension_type)
        return [entry for entry in self.list() if entry.extension_type == wanted]

    def trust_of(self, extension_id: str, version: str | None = None) -> ExtensionTrust:
        return self.get(extension_id, version).trust

    def health_of(self, extension_id: str, version: str | None = None) -> ExtensionHealth:
        return self.get(extension_id, version).health

    def get_health(self, extension_id: str, version: str | None = None) -> ExtensionHealth:
        return self.health_of(extension_id, version)

    def get_provenance(self, extension_id: str, version: str | None = None) -> ExtensionProvenance:
        return self.get(extension_id, version).manifest.source_provenance

    def identities(self) -> list[str]:
        return [entry.identity for entry in self.list()]

    def provides_index(self) -> dict[str, tuple[str, ...]]:
        """capability/feature token -> deterministic ``id@version`` list."""
        index: dict[str, list[str]] = {}
        for entry in self.list():
            for capability in entry.manifest.declared_capabilities:
                index.setdefault(capability, []).append(entry.identity)
            for feature in entry.manifest.provides.provides_feature:
                index.setdefault(feature, []).append(entry.identity)
        return {token: tuple(values) for token, values in sorted(index.items())}

    def provider_conflicts(self) -> tuple[Any, ...]:
        return provider_conflicts(self.provides_index())

    # -- host-side state changes ----------------------------------------

    def advance(self, extension_id: str, version: str, to: ExtensionLifecycle) -> RegisteredExtension:
        """Host-controlled lifecycle transition. Never callable by content."""
        entry = self.get(extension_id, version)
        allowed = ALLOWED_TRANSITIONS.get(entry.lifecycle, ())
        if to not in allowed:
            raise ExtensionError(
                ExtensionErrorCode.LIFECYCLE_INVALID,
                f"{entry.identity}: {entry.lifecycle.value} -> {to.value} is not allowed",
            )
        updated = entry.model_copy(update={"lifecycle": to})
        self._entries[(extension_id, version)] = updated
        return updated

    def quarantine(self, extension_id: str, version: str, reason: str) -> RegisteredExtension:
        entry = self.get(extension_id, version)
        if entry.lifecycle is ExtensionLifecycle.QUARANTINED:
            return entry
        updated = entry.model_copy(
            update={
                "lifecycle": ExtensionLifecycle.QUARANTINED,
                "health": ExtensionHealth(
                    status=ExtensionHealthStatus.DEGRADED,
                    checks=("quarantined",),
                    note=reason[:300],
                ),
            }
        )
        self._entries[(extension_id, version)] = updated
        return updated

    def set_health(self, extension_id: str, version: str, health: ExtensionHealth) -> RegisteredExtension:
        entry = self.get(extension_id, version)
        updated = entry.model_copy(update={"health": health})
        self._entries[(extension_id, version)] = updated
        return updated

    # -- evaluation -------------------------------------------------------

    def validate(self, manifest: ExtensionManifest, *, raw: dict[str, Any] | None = None) -> ExtensionValidation:
        return self._validator.validate(manifest, raw=raw)

    def check_compatibility(self, extension_id: str, version: str | None = None, host: HostProfile | None = None) -> CompatibilityResult:
        entry = self.get(extension_id, version)
        return check_compatibility(entry.manifest, host or self._host or HostProfile())

    def resolve(self, request: ResolutionRequest | None = None, **kwargs: object) -> Resolution:
        return ExtensionResolver(self).resolve(request or ResolutionRequest(**kwargs))  # type: ignore[arg-type]

    # -- allowlisted queries ---------------------------------------------

    def query(self, name: str, **params: Any) -> Any:
        """The only dynamic entry point. Unknown names fail closed."""
        if name not in ALLOWED_QUERIES:
            raise ExtensionError(ExtensionErrorCode.QUERY_UNKNOWN, f"unsupported query: {name}")
        handler = {
            "list_extensions": lambda: [entry.summary() for entry in self.list()],
            "get_extension": lambda: self.get(str(params.get("extension_id", "")), params.get("version")).summary(),
            "list_by_type": lambda: [
                entry.summary() for entry in self.list_by_type(str(params.get("extension_type", "")))
            ],
            "resolve_extension": lambda: self.resolve(
                ResolutionRequest(
                    extension_id=str(params.get("extension_id", "")),
                    version_constraint=str(params.get("version_constraint", "")),
                    provide=str(params.get("provide", "")),
                )
            ).model_dump(mode="json"),
            "check_compatibility": lambda: self.check_compatibility(
                str(params.get("extension_id", "")), params.get("version")
            ).model_dump(mode="json"),
            "get_provenance": lambda: self.get_provenance(
                str(params.get("extension_id", "")), params.get("version")
            ).model_dump(mode="json"),
            "get_health": lambda: self.get_health(
                str(params.get("extension_id", "")), params.get("version")
            ).model_dump(mode="json"),
        }[name]
        return handler()
