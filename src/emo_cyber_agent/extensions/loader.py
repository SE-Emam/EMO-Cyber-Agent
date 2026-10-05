"""Extension loader — POST-RC-014.

The loader is the single place where a discovered manifest can become a
registered, loadable extension, and it is deliberately boring about it:

    discover -> validate manifest -> compatibility -> dependency graph
             -> provenance -> trust -> register -> load only when required

Fail-closed at every step: invalid manifests are rejected or
quarantined, incompatible extensions never reach ``compatible``,
dependency cycles are refused before loading, and untrusted content
never becomes loadable — no matter how it was discovered.

Two rules are absolute. Discovery and registration never import
extension code (the only import happens in ``load_implementation``,
behind an explicit host switch), and the loader performs no install,
upgrade, removal, network bootstrap, background thread or filesystem
mutation of its own. Installation belongs to pip/pipx/host tooling;
runtime setup belongs to the Core-controlled lifecycle that follows.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.extensions.compatibility import CompatibilityResult, HostProfile, check_compatibility
from emo_cyber_agent.extensions.conflicts import ExtensionConflict, detect_cycles
from emo_cyber_agent.extensions.discovery import (
    DiscoveredSource,
    DiscoveryReport,
    EntryPointRef,
    discover_directory,
    parse_entry_target,
)
from emo_cyber_agent.extensions.errors import ExtensionError, ExtensionErrorCode
from emo_cyber_agent.extensions.provenance import ProvenanceAssessment, assess_provenance
from emo_cyber_agent.extensions.registry import ExtensionRegistry
from emo_cyber_agent.extensions.spec import (
    ExtensionConflictKind,
    ExtensionHealth,
    ExtensionHealthStatus,
    ExtensionLifecycle,
    ExtensionSourceClass,
    ExtensionTrustState,
)
from emo_cyber_agent.extensions.trust import evaluate_trust, trust_allows_load
from emo_cyber_agent.extensions.validator import ExtensionValidation, ExtensionValidator

__all__ = [
    "ExtensionLoader",
    "LoadReport",
    "default_importer",
]


class LoadReport(BaseModel):
    """Frozen record of one ingest or load attempt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    origin: str = Field(default="", max_length=500)
    extension_id: str = Field(default="", max_length=80)
    version: str = Field(default="", max_length=32)
    trail: tuple[ExtensionLifecycle, ...] = Field(default_factory=tuple)
    validation: ExtensionValidation | None = None
    compatibility: CompatibilityResult | None = None
    provenance: ProvenanceAssessment | None = None
    trust_state: str = ""
    conflicts: tuple[ExtensionConflict, ...] = Field(default_factory=tuple)
    registered: bool = False
    loaded: bool = False
    reason: str = Field(default="", max_length=500)

    @property
    def identity(self) -> str:
        return f"{self.extension_id}@{self.version}" if self.extension_id else self.origin


def default_importer(target: str) -> Any:
    """Explicit, validated import path for an implementation entry point.

    The only import in the layer. Reached exclusively from
    ``load_implementation`` after trust evaluation, never from
    discovery, validation or registration."""
    parsed = parse_entry_target(target)
    if parsed is None:
        raise ExtensionError(ExtensionErrorCode.ENTRYPOINT_INVALID, f"malformed entry point: {target[:80]}")
    module_name, attribute = parsed
    module = importlib.import_module(module_name)
    value: Any = module
    for part in attribute.split("."):
        value = getattr(value, part)
    return value


class ExtensionLoader:
    """Host-controlled loader. Constructed per call site, never global."""

    def __init__(
        self,
        registry: ExtensionRegistry,
        *,
        host: HostProfile | None = None,
        allow_code_load: bool = False,
        validator: ExtensionValidator | None = None,
        official_publishers: tuple[str, ...] | None = None,
    ) -> None:
        self._registry = registry
        self._host = host or HostProfile()
        self._allow_code_load = allow_code_load
        self._validator = validator or ExtensionValidator()
        self._official_publishers = official_publishers

    @property
    def registry(self) -> ExtensionRegistry:
        return self._registry

    # -- ingest -----------------------------------------------------------

    def ingest(self, source: DiscoveredSource, *, verification: tuple[str, ...] = ()) -> LoadReport:
        """Run the full pipeline for one discovered source."""
        trail: list[ExtensionLifecycle] = [ExtensionLifecycle.DISCOVERED]

        if source.manifest is None:
            reason = "; ".join(source.errors)[:400] or "manifest missing"
            trail.append(ExtensionLifecycle.REJECTED)
            return LoadReport(origin=source.origin, trail=tuple(trail), registered=False, reason=reason)

        manifest = source.manifest
        validation = self._validator.validate(manifest, raw=manifest.model_dump(mode="json"))
        if not validation.valid:
            target = ExtensionLifecycle.REJECTED if validation.authority_rejection else ExtensionLifecycle.QUARANTINED
            trail.append(target)
            trust_state = (
                ExtensionTrustState.REJECTED.value
                if target is ExtensionLifecycle.REJECTED
                else ExtensionTrustState.QUARANTINED.value
            )
            report = LoadReport(
                origin=source.origin,
                extension_id=manifest.extension_id,
                version=manifest.version,
                trail=tuple(trail),
                validation=validation,
                trust_state=trust_state,
                registered=False,
                reason="; ".join(validation.errors[:3])[:400],
            )
            if target is ExtensionLifecycle.QUARANTINED:
                report = self._register_quarantined(source, report, trail)
            return report
        trail.append(ExtensionLifecycle.VALIDATED)

        compatibility = check_compatibility(manifest, self._host)
        if not compatibility.compatible:
            trail.append(ExtensionLifecycle.QUARANTINED)
            trust = evaluate_trust(
                manifest,
                source_class=source.source_class,
                validation=validation,
                compatibility_ok=False,
                official_publishers=self._official_publishers,
            )
            report = LoadReport(
                origin=source.origin,
                extension_id=manifest.extension_id,
                version=manifest.version,
                trail=tuple(trail),
                validation=validation,
                compatibility=compatibility,
                trust_state=trust.state.value,
                conflicts=tuple(),
                registered=False,
                reason="; ".join(compatibility.reasons[:3])[:400],
            )
            # Visible but never resolvable: incompatible content is recorded
            # so operators can inspect it, and stays in the quarantined state.
            return self._register_quarantined(source, report, trail)
        trail.append(ExtensionLifecycle.COMPATIBLE)

        conflicts = self._dependency_conflicts(manifest)
        if conflicts:
            trail.append(ExtensionLifecycle.QUARANTINED)
            trust = evaluate_trust(
                manifest,
                source_class=source.source_class,
                validation=validation,
                official_publishers=self._official_publishers,
            )
            report = LoadReport(
                origin=source.origin,
                extension_id=manifest.extension_id,
                version=manifest.version,
                trail=tuple(trail),
                validation=validation,
                compatibility=compatibility,
                trust_state=ExtensionTrustState.QUARANTINED.value,
                conflicts=conflicts,
                registered=False,
                reason="; ".join(f"{c.kind.value}:{c.subject}" for c in conflicts[:3])[:400],
            )
            return self._register_quarantined(source, report, trail)

        provenance = assess_provenance(
            manifest.source_provenance,
            artifact=manifest.artifact_identity,
        )
        trust = evaluate_trust(
            manifest,
            source_class=source.source_class,
            validation=validation,
            compatibility_ok=True,
            provenance=provenance,
            verification=verification,
            official_publishers=self._official_publishers,
        )
        if trust.state in (ExtensionTrustState.REJECTED, ExtensionTrustState.QUARANTINED):
            trail.append(
                ExtensionLifecycle.REJECTED
                if trust.state is ExtensionTrustState.REJECTED
                else ExtensionLifecycle.QUARANTINED
            )
            report = LoadReport(
                origin=source.origin,
                extension_id=manifest.extension_id,
                version=manifest.version,
                trail=tuple(trail),
                validation=validation,
                compatibility=compatibility,
                provenance=provenance,
                trust_state=trust.state.value,
                registered=False,
                reason="; ".join(trust.reasons[:3])[:400],
            )
            if trust.state is ExtensionTrustState.QUARANTINED:
                report = self._register_quarantined(source, report, trail)
            return report
        trail.append(ExtensionLifecycle.TRUST_EVALUATED)

        self._registry.register(
            manifest,
            trust=trust,
            origin=source.origin,
            lifecycle=ExtensionLifecycle.REGISTERED,
            health=ExtensionHealth(status=ExtensionHealthStatus.UNKNOWN, checks=("registered",)),
        )
        trail.append(ExtensionLifecycle.REGISTERED)
        if trust_allows_load(trust):
            self._registry.advance(manifest.extension_id, manifest.version, ExtensionLifecycle.LOADABLE)
            trail.append(ExtensionLifecycle.LOADABLE)

        return LoadReport(
            origin=source.origin,
            extension_id=manifest.extension_id,
            version=manifest.version,
            trail=tuple(trail),
            validation=validation,
            compatibility=compatibility,
            provenance=provenance,
            trust_state=trust.state.value,
            registered=True,
            reason="; ".join(trust.reasons[:2])[:400],
        )

    def ingest_directory(
        self,
        directory: str | Path,
        *,
        source_class: ExtensionSourceClass = ExtensionSourceClass.THIRD_PARTY,
        verification: tuple[str, ...] = (),
    ) -> tuple[LoadReport, ...]:
        """Discover a directory, then ingest each source in sorted order."""
        report: DiscoveryReport = discover_directory(directory, source_class=source_class)
        return tuple(self.ingest(source, verification=verification) for source in report.sources)

    def ingest_entry_point(self, ref: EntryPointRef, *, source_class: ExtensionSourceClass) -> LoadReport:
        """Record a deferred entry point without importing it.

        No manifest can be read without code execution for an entry
        point reference, so the report stays empty and the reference is
        kept for an explicit, host-initiated load step."""
        return LoadReport(
            origin=f"entrypoint:{ref.distribution_name}:{ref.name}",
            trail=(ExtensionLifecycle.DISCOVERED,),
            registered=False,
            reason="entry point deferred: manifest requires explicit host load",
        )

    # -- explicit load ----------------------------------------------------

    def load_implementation(
        self,
        extension_id: str,
        version: str,
        *,
        importer: Any = None,
    ) -> LoadReport:
        """Import an implementation object. The only import in the layer.

        Refuses when code loading is off, when trust is absent, when the
        type is declarative, or when the entry point is malformed. A
        failed import quarantines the extension instead of retrying."""
        if not self._allow_code_load:
            raise ExtensionError(ExtensionErrorCode.LOAD_REFUSED, "code loading is disabled for this loader")

        entry = self._registry.get(extension_id, version)
        if not trust_allows_load(entry.trust):
            raise ExtensionError(
                ExtensionErrorCode.LOAD_REFUSED,
                f"trust does not allow loading {entry.identity}: {entry.trust.state.value}",
            )
        declarative_only = entry.manifest.type_value in (
            "skill",
            "skill_pack",
            "task",
            "playbook",
            "report_template",
            "threat_method",
            "threat_ruleset",
            "evaluation_dataset",
        )
        if declarative_only:
            raise ExtensionError(
                ExtensionErrorCode.LOAD_REFUSED,
                f"{entry.identity} is declarative: content loads through its contract, not through code",
            )
        ep = entry.manifest.entrypoint_metadata
        if ep.kind.value != "implementation" or not ep.target:
            self._registry.quarantine(extension_id, version, "implementation entry point missing")
            raise ExtensionError(ExtensionErrorCode.ENTRYPOINT_INVALID, f"{entry.identity} has no implementation target")

        target = entry.lifecycle
        if target not in (ExtensionLifecycle.LOADABLE, ExtensionLifecycle.LOADED, ExtensionLifecycle.REGISTERED):
            raise ExtensionError(
                ExtensionErrorCode.LOAD_REFUSED,
                f"{entry.identity} lifecycle {target.value} does not permit loading",
            )

        try:
            loaded = (importer or default_importer)(ep.target)
        except ExtensionError:
            self._registry.quarantine(extension_id, version, "entry point rejected")
            raise
        except Exception as exc:  # noqa: BLE001 - import failures are content failures
            self._registry.quarantine(extension_id, version, f"import failed: {type(exc).__name__}")
            raise ExtensionError(
                ExtensionErrorCode.LOAD_FAILED,
                f"import failed for {entry.identity}: {type(exc).__name__}: {str(exc)[:200]}",
            ) from None

        if entry.lifecycle is ExtensionLifecycle.LOADABLE:
            self._registry.advance(extension_id, version, ExtensionLifecycle.LOADED)
        self._registry.set_health(
            extension_id,
            version,
            ExtensionHealth(status=ExtensionHealthStatus.HEALTHY, checks=("loaded",), note=ep.target[:200]),
        )
        return LoadReport(
            origin=entry.origin,
            extension_id=extension_id,
            version=version,
            trail=(
                ExtensionLifecycle.REGISTERED,
                ExtensionLifecycle.LOADABLE,
                ExtensionLifecycle.LOADED,
            ),
            trust_state=entry.trust.state.value,
            registered=True,
            loaded=True,
            reason=f"implementation object type={type(loaded).__name__}"[:200],
        )

    # -- internals --------------------------------------------------------

    def _register_quarantined(self, source: DiscoveredSource, report: LoadReport, trail: list[ExtensionLifecycle]) -> LoadReport:
        """Register observable but non-resolvable state for inspection."""
        manifest = source.manifest
        if manifest is None:
            return report
        from emo_cyber_agent.extensions.trust import trust_allows_registration

        trust = evaluate_trust(
            manifest,
            source_class=source.source_class,
            validation=report.validation or ExtensionValidation(),
            compatibility_ok=report.compatibility.compatible if report.compatibility else False,
            official_publishers=self._official_publishers,
        )
        if trust.state not in (ExtensionTrustState.QUARANTINED, ExtensionTrustState.REJECTED):
            trust = trust.model_copy(update={"state": ExtensionTrustState.QUARANTINED})
        if not trust_allows_registration(trust):
            return report
        try:
            self._registry.register(
                manifest,
                trust=trust,
                origin=source.origin,
                lifecycle=ExtensionLifecycle.QUARANTINED,
                health=ExtensionHealth(status=ExtensionHealthStatus.DEGRADED, checks=("quarantined",)),
            )
        except ExtensionError:
            return report
        return report.model_copy(update={"registered": True})

    def _dependency_conflicts(self, manifest: Any) -> tuple[ExtensionConflict, ...]:
        conflicts: list[ExtensionConflict] = []
        graph: dict[str, tuple[str, ...]] = {
            manifest.extension_id: tuple(dep.extension_id for dep in manifest.dependencies)
        }
        seen: set[str] = set()
        queue = [dep.extension_id for dep in manifest.dependencies]
        while queue:
            node = queue.pop(0)
            if node in seen:
                continue
            seen.add(node)
            versions = self._registry.versions(node)
            if not versions:
                conflicts.append(
                    ExtensionConflict(
                        kind=ExtensionConflictKind.DEPENDENCY_MISSING,
                        subject=node,
                        note="required dependency not registered",
                    )
                )
                continue
            entry = self._registry.get(node, versions[0])
            graph.setdefault(node, tuple(dep.extension_id for dep in entry.manifest.dependencies))
            queue.extend(dep.extension_id for dep in entry.manifest.dependencies)

        for cycle in detect_cycles(graph):
            conflicts.append(
                ExtensionConflict(
                    kind=ExtensionConflictKind.DEPENDENCY_CYCLE,
                    subject=" -> ".join(cycle),
                    candidates=cycle,
                    note="dependency cycle refused before load",
                )
            )
        return tuple(conflicts)
