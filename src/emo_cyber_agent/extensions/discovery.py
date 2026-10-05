"""Extension discovery — POST-RC-014.

Discovery is metadata-first and import-free by construction. The chain
stops at the manifest:

    installed distribution -> metadata -> manifest -> (validation happens
    next, in the loader)   — never  discover -> import -> initialize

PyPA entry points are supported as a *discovery mechanism* only: the
group ``emo_cyber_agent.extensions`` yields names and ``module:attr``
strings, which are recorded as deferred references. An entry point is
never ``load()``-ed here, so a hostile package cannot run code, open a
socket, spawn a process or mutate the filesystem just by being listed in
the environment. Entry point discovery never implies trust or
permission: the loader still validates, checks compatibility, resolves
dependencies, assesses provenance and evaluates trust before anything
becomes registered, and only an explicit load step ever imports.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.extensions.errors import ExtensionError, ExtensionErrorCode
from emo_cyber_agent.extensions.manifest import load_manifest_file, normalize_manifest_dict
from emo_cyber_agent.extensions.spec import ExtensionManifest, ExtensionSourceClass

__all__ = [
    "ENTRY_POINT_GROUP",
    "DiscoveredSource",
    "DiscoveryReport",
    "DistributionRecord",
    "EntryPointRef",
    "discover_directory",
    "discover_distributions",
    "discover_entry_points",
    "discover_manifest_file",
    "parse_entry_target",
]

ENTRY_POINT_GROUP = "emo_cyber_agent.extensions"
"""Dedicated namespace: unrelated groups are never scanned."""

_TARGET_RE = re.compile(r"^(?P<module>[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)*):(?P<attr>[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)*)$")

MANIFEST_GLOBS: tuple[str, ...] = ("*.extension.yaml", "*.extension.yml", "*.extension.json")


class EntryPointRef(BaseModel):
    """A deferred entry point. ``value`` is data until an explicit load."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., min_length=1, max_length=120)
    value: str = Field(..., min_length=1, max_length=300)
    group: str = Field(default=ENTRY_POINT_GROUP, max_length=120)
    distribution_name: str = Field(default="", max_length=200)
    distribution_version: str = Field(default="", max_length=64)
    deferred: bool = True

    @property
    def malformed(self) -> bool:
        return parse_entry_target(self.value) is None


class DistributionRecord(BaseModel):
    """Installed-distribution metadata. No code, no import."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    distribution_name: str = Field(..., min_length=1, max_length=200)
    distribution_version: str = Field(default="", max_length=64)
    entry_points: tuple[EntryPointRef, ...] = Field(default_factory=tuple)


class DiscoveredSource(BaseModel):
    """One discovered origin: a manifest file or a deferred entry point."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    origin: str = Field(..., min_length=1, max_length=500)
    source_class: ExtensionSourceClass = ExtensionSourceClass.THIRD_PARTY
    manifest: ExtensionManifest | None = None
    manifest_source: str = Field(default="manifest_file", max_length=64)
    errors: tuple[str, ...] = Field(default_factory=tuple)
    entry_points: tuple[EntryPointRef, ...] = Field(default_factory=tuple)

    @property
    def identity(self) -> str:
        if self.manifest is not None:
            return f"{self.manifest.extension_id}@{self.manifest.version}"
        return self.origin

    @property
    def ok(self) -> bool:
        return self.manifest is not None and not self.errors


class DiscoveryReport(BaseModel):
    """Discovery output. ``imported`` is structurally always zero."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sources: tuple[DiscoveredSource, ...] = Field(default_factory=tuple)
    distributions: tuple[DistributionRecord, ...] = Field(default_factory=tuple)
    scanned: int = 0
    imported: int = 0


def parse_entry_target(value: str) -> tuple[str, str] | None:
    """Parse ``module:attribute`` without importing anything."""
    match = _TARGET_RE.match((value or "").strip())
    if match is None:
        return None
    return match.group("module"), match.group("attr")


def discover_entry_points(
    group: str = ENTRY_POINT_GROUP,
    *,
    entry_points: Any = None,
) -> tuple[EntryPointRef, ...]:
    """List entry points in our namespace. Never calls ``load()``."""
    if entry_points is None:
        try:
            from importlib.metadata import entry_points as _entry_points

            selected = _entry_points(group=group)
        except Exception:  # noqa: BLE001 - a broken environment must not crash discovery
            return ()
    else:
        selected = entry_points

    refs: list[EntryPointRef] = []
    for item in selected:
        distribution_name = ""
        distribution_version = ""
        dist = getattr(item, "dist", None)
        if dist is not None:
            distribution_name = str(getattr(dist, "name", "") or "")
            distribution_version = str(getattr(dist, "version", "") or "")
        refs.append(
            EntryPointRef(
                name=str(getattr(item, "name", "")),
                value=str(getattr(item, "value", "")),
                group=str(getattr(item, "group", group) or group),
                distribution_name=distribution_name,
                distribution_version=distribution_version,
                deferred=True,
            )
        )
    return tuple(sorted(refs, key=lambda ref: (ref.distribution_name, ref.name, ref.value)))


def discover_distributions(*, distributions: Any = None) -> tuple[DistributionRecord, ...]:
    """Installed distributions carrying our entry point group.

    Metadata only: importlib.metadata reads ``*.dist-info`` files, it does
    not import the distribution's modules."""
    if distributions is None:
        try:
            from importlib.metadata import distributions as _distributions

            distributions = _distributions()
        except Exception:  # noqa: BLE001 - metadata access never fails a host
            return ()

    records: list[DistributionRecord] = []
    for dist in distributions:
        try:
            name = str(dist.metadata.get("Name", "") or "")
            version = str(dist.metadata.get("Version", "") or "")
            points: list[EntryPointRef] = []
            for entry_point in dist.entry_points:
                if getattr(entry_point, "group", "") != ENTRY_POINT_GROUP:
                    continue
                points.append(
                    EntryPointRef(
                        name=str(entry_point.name),
                        value=str(entry_point.value),
                        group=ENTRY_POINT_GROUP,
                        distribution_name=name,
                        distribution_version=version,
                        deferred=True,
                    )
                )
        except Exception:  # noqa: BLE001 - malformed dist-info is skipped, not fatal
            continue
        if name and points:
            records.append(
                DistributionRecord(
                    distribution_name=name,
                    distribution_version=version,
                    entry_points=tuple(sorted(points, key=lambda ref: ref.name)),
                )
            )
    return tuple(sorted(records, key=lambda record: record.distribution_name))


def discover_manifest_file(
    path: str | Path,
    *,
    source_class: ExtensionSourceClass = ExtensionSourceClass.THIRD_PARTY,
    origin: str | None = None,
) -> DiscoveredSource:
    """Read and parse one manifest file. Parsing never imports code."""
    target = Path(path)
    reference = origin or str(target)
    try:
        manifest = load_manifest_file(target)
    except ExtensionError as exc:
        return DiscoveredSource(
            origin=reference,
            source_class=source_class,
            manifest=None,
            errors=(f"{exc.code.value}:{exc.message}",),
        )
    except OSError as exc:
        return DiscoveredSource(
            origin=reference,
            source_class=source_class,
            manifest=None,
            errors=(f"{ExtensionErrorCode.MANIFEST_MISSING.value}:{exc}",),
        )
    return DiscoveredSource(
        origin=reference,
        source_class=source_class,
        manifest=manifest,
        manifest_source="manifest_file",
    )


def discover_directory(
    directory: str | Path,
    *,
    source_class: ExtensionSourceClass = ExtensionSourceClass.THIRD_PARTY,
    entry_points: tuple[EntryPointRef, ...] = (),
) -> DiscoveryReport:
    """Sorted, metadata-first directory scan. Reads files, imports nothing."""
    root = Path(directory)
    if not root.is_dir():
        raise ExtensionError(ExtensionErrorCode.MANIFEST_MISSING, f"not a directory: {root}")

    files: list[Path] = []
    for pattern in MANIFEST_GLOBS:
        files.extend(root.rglob(pattern))
    unique = sorted({path for path in files}, key=lambda path: str(path.relative_to(root)))

    sources = tuple(
        discover_manifest_file(path, source_class=source_class, origin=str(path))
        for path in unique
    )
    return DiscoveryReport(
        sources=sources,
        distributions=(),
        scanned=len(unique),
        imported=0,
    )


def source_from_dict(
    data: dict[str, Any],
    *,
    origin: str,
    source_class: ExtensionSourceClass = ExtensionSourceClass.THIRD_PARTY,
) -> DiscoveredSource:
    """Build a discovery record from an already-parsed mapping.

    Used by tests and by hosts that carry manifest dictionaries from
    their own metadata readers. Still no import, still no validation —
    validation is the loader's job, after discovery."""
    from emo_cyber_agent.extensions.manifest import manifest_from_dict

    try:
        manifest = manifest_from_dict(normalize_manifest_dict(data))
    except ExtensionError as exc:
        return DiscoveredSource(
            origin=origin,
            source_class=source_class,
            manifest=None,
            errors=(f"{exc.code.value}:{exc.message}",),
        )
    return DiscoveredSource(
        origin=origin,
        source_class=source_class,
        manifest=manifest,
        manifest_source="distribution_metadata",
    )
