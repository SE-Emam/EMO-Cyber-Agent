"""Extension catalog and content bridges — POST-RC-014.

The catalog does two jobs, both read-only:

* load *official* extension manifests (the shipped reference set) into a
  registry with host-assigned official trust — trust is assigned by this
  loader, never read from the document;
* materialize declarative content by reusing the **existing** trusted
  loaders and validators (tool packs, skill packs, skills, tasks,
  playbooks, report templates, threat methods, evaluation datasets,
  verification strategies). The extension layer discovers and connects;
  it never re-implements those contracts, never widens their taxonomies,
  and never grants anything they do not already grant.

Materialization reads package-scoped resource paths only: every path is
re-validated with the hardened path rules before a byte is read, so
``../../etc/passwd`` and absolute paths are refused before I/O.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from emo_cyber_agent.extensions.discovery import discover_directory
from emo_cyber_agent.extensions.errors import ExtensionError, ExtensionErrorCode
from emo_cyber_agent.extensions.loader import ExtensionLoader, LoadReport
from emo_cyber_agent.extensions.registry import ExtensionRegistry
from emo_cyber_agent.extensions.spec import (
    TRUSTED_STATES,
    ExtensionManifest,
    ExtensionResource,
    ExtensionSourceClass,
)
from emo_cyber_agent.extensions.compatibility import HostProfile

__all__ = [
    "OFFICIAL_PUBLISHER",
    "READ_ACTIONS",
    "resolve_resource_path",
    "build_read_registry",
    "content_resource",
    "extension_roots",
    "load_official_extensions",
    "read_extensions",
    "materialize_content",
    "materialize_evaluation_dataset",
    "materialize_skill",
    "materialize_skill_pack",
    "materialize_task",
    "materialize_playbook",
    "materialize_report_template",
    "materialize_threat_method",
    "materialize_tool_pack",
    "materialize_verification_strategy",
    "read_resource_text",
    "verify_extension_contract",
]

OFFICIAL_PUBLISHER = "emo-cyber-agent"
"""Publisher identity the host allowlists for official extensions."""

CONTENT_RESOURCE_ID = "content"


class MaterializedContent(BaseModel):
    """Text content read from an extension's package-scoped resource."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    extension_id: str
    version: str
    extension_type: str
    resource_id: str
    path: str
    text: str = ""


def content_resource(manifest: ExtensionManifest) -> ExtensionResource:
    """The extension's primary content resource (``resource_id=content``)."""
    for resource in manifest.resources:
        if resource.resource_id == CONTENT_RESOURCE_ID:
            return resource
    raise ExtensionError(
        ExtensionErrorCode.RESOURCE_DENIED,
        f"{manifest.extension_id}@{manifest.version} declares no 'content' resource",
    )


def resolve_resource_path(root: str | Path, resource: ExtensionResource) -> Path:
    """Resolve a package-scoped resource to a confined file path.

    Hardened path rules first (traversal, percent-encoding, absolute,
    null byte), then a containment check against the package root, then
    existence — all before any read happens."""
    from emo_cyber_agent.core.repository import RepositoryError, normalize_path

    try:
        relative = normalize_path(resource.path)
    except RepositoryError as exc:
        raise ExtensionError(ExtensionErrorCode.RESOURCE_DENIED, f"{resource.resource_id}: {exc}") from None

    base = Path(root).resolve()
    target = (base / relative).resolve()
    if not str(target).startswith(str(base)):
        raise ExtensionError(
            ExtensionErrorCode.RESOURCE_DENIED,
            f"{resource.resource_id}: path escapes package root",
        )
    if not target.is_file():
        raise ExtensionError(
            ExtensionErrorCode.RESOURCE_DENIED,
            f"{resource.resource_id}: missing resource {relative}",
        )
    return target


def read_resource_text(root: str | Path, resource: ExtensionResource) -> str:
    """Read one package-scoped resource. Path-confined, read-only."""
    target = resolve_resource_path(root, resource)
    try:
        return target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExtensionError(ExtensionErrorCode.RESOURCE_DENIED, f"{resource.resource_id}: {exc}") from None


def materialize_content(root: str | Path, manifest: ExtensionManifest) -> MaterializedContent:
    """Read the manifest's content resource into a frozen record."""
    resource = content_resource(manifest)
    text = read_resource_text(root, resource)
    return MaterializedContent(
        extension_id=manifest.extension_id,
        version=manifest.version,
        extension_type=manifest.type_value,
        resource_id=resource.resource_id,
        path=resource.path,
        text=text,
    )


# ---------------------------------------------------------------------------
# Bridges to the existing trusted loaders (never re-implemented here)
# ---------------------------------------------------------------------------


def _yaml_doc(text: str, *, extension_id: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, f"yaml missing: {exc}") from exc
    try:
        doc = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 - content failure
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, f"{extension_id}: malformed YAML: {exc}") from None
    if not isinstance(doc, dict):
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, f"{extension_id}: content must be a mapping")
    return doc


def materialize_tool_pack(root: str | Path, manifest: ExtensionManifest) -> Any:
    """Tool pack content through POST-RC-007's own loader and validator."""
    from emo_cyber_agent.tools.packs.catalog import spec_from_yaml_text

    content = materialize_content(root, manifest)
    return spec_from_yaml_text(content.text)


def materialize_skill_pack(root: str | Path, manifest: ExtensionManifest) -> Any:
    """Skill pack content through POST-RC-006's own loader and validator."""
    from emo_cyber_agent.skills.packs.catalog import spec_from_yaml_text

    content = materialize_content(root, manifest)
    return spec_from_yaml_text(content.text)


def materialize_skill(root: str | Path, manifest: ExtensionManifest) -> Any:
    """Single skill through the existing ``SkillSpec`` contract."""
    from emo_cyber_agent.skills.spec import SkillSpec

    content = materialize_content(root, manifest)
    doc = _yaml_doc(content.text, extension_id=manifest.extension_id)
    flat = doc.get("skill", doc) if isinstance(doc.get("skill"), dict) else doc
    try:
        return SkillSpec(**flat)
    except Exception as exc:  # noqa: BLE001 - typed below
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, f"{manifest.extension_id}: skill invalid: {exc}") from None


def materialize_task(root: str | Path, manifest: ExtensionManifest) -> Any:
    from emo_cyber_agent.tasks.library import spec_from_yaml_text

    content = materialize_content(root, manifest)
    return spec_from_yaml_text(content.text)


def materialize_playbook(root: str | Path, manifest: ExtensionManifest) -> Any:
    from emo_cyber_agent.playbooks.library import spec_from_yaml_text

    content = materialize_content(root, manifest)
    return spec_from_yaml_text(content.text)


def materialize_report_template(root: str | Path, manifest: ExtensionManifest) -> Any:
    from emo_cyber_agent.report_templates.library import spec_from_yaml_text

    content = materialize_content(root, manifest)
    return spec_from_yaml_text(content.text)


def materialize_verification_strategy(root: str | Path, manifest: ExtensionManifest) -> Any:
    """Verification strategy through POST-RC-012's official file loader.

    Reads the confined resource in place: no temporary copies, no
    writes, no re-implementation of the strategy contract."""
    from emo_cyber_agent.verification.strategy import load_strategy_file

    resource = content_resource(manifest)
    target = resolve_resource_path(root, resource)
    try:
        strategies = load_strategy_file(target)
    except ExtensionError:
        raise
    except Exception as exc:  # noqa: BLE001 - content failure typed by us
        raise ExtensionError(
            ExtensionErrorCode.MANIFEST_INVALID,
            f"{manifest.extension_id}: strategy invalid: {exc}",
        ) from None
    if len(strategies) == 1:
        return strategies[0]
    return strategies


def materialize_threat_method(root: str | Path, manifest: ExtensionManifest) -> tuple[Any, tuple[Any, ...]]:
    """Threat method + rules through POST-RC-009's models.

    Non-authoritative by construction: a method carries categories and
    rules only — no severity, no Finding, no execution."""
    from emo_cyber_agent.threat_modeling.spec import ThreatMethod, ThreatRule

    content = materialize_content(root, manifest)
    doc = _yaml_doc(content.text, extension_id=manifest.extension_id)
    method_doc: Any = doc.get("method")
    if not isinstance(method_doc, dict):
        method_doc = doc
    rules_doc: Any = doc.get("rules")
    if not isinstance(rules_doc, list):
        rules_doc = []
    try:
        method = ThreatMethod(**method_doc)
        rules = tuple(ThreatRule(**rule) for rule in rules_doc)
    except Exception as exc:  # noqa: BLE001 - typed below
        raise ExtensionError(
            ExtensionErrorCode.MANIFEST_INVALID, f"{manifest.extension_id}: threat method invalid: {exc}"
        ) from None
    return method, rules


def materialize_evaluation_dataset(root: str | Path, manifest: ExtensionManifest) -> Any:
    """Evaluation dataset through POST-RC-013's blind loader.

    The dataset stays a dataset: classification travels with it, and no
    holdout label may be copied into production configuration."""
    from emo_cyber_agent.evaluation.datasets import load_dataset

    resource = content_resource(manifest)
    try:
        from emo_cyber_agent.core.repository import normalize_path

        relative = normalize_path(resource.path)
    except Exception as exc:  # noqa: BLE001 - path rules
        raise ExtensionError(ExtensionErrorCode.RESOURCE_DENIED, f"{manifest.extension_id}: {exc}") from None
    dataset_root = (Path(root).resolve() / relative).parent
    if not (dataset_root / "dataset.json").is_file():
        raise ExtensionError(
            ExtensionErrorCode.RESOURCE_DENIED,
            f"{manifest.extension_id}: dataset manifest missing at {relative}",
        )
    return load_dataset(dataset_root)


def materialize_verification_adapter(manifest: ExtensionManifest, *, importer: Any = None) -> Any:
    """Load an executable adapter implementation through the loader path."""
    from emo_cyber_agent.extensions.loader import default_importer

    ep = manifest.entrypoint_metadata
    if ep.kind.value != "implementation" or not ep.target:
        raise ExtensionError(ExtensionErrorCode.ENTRYPOINT_INVALID, f"{manifest.extension_id}: no implementation target")
    try:
        loaded = (importer or default_importer)(ep.target)
    except ExtensionError:
        raise
    except Exception as exc:  # noqa: BLE001 - import failure is typed
        raise ExtensionError(
            ExtensionErrorCode.LOAD_FAILED, f"{manifest.extension_id}: import failed: {type(exc).__name__}"
        ) from None
    if callable(loaded) and not hasattr(loaded, "provenance"):
        loaded = loaded()
    return loaded


# ---------------------------------------------------------------------------
# Official catalog
# ---------------------------------------------------------------------------


def verify_extension_contract(manifest: ExtensionManifest) -> tuple[str, ...]:
    """Re-run the contract checks an official extension must satisfy."""
    from emo_cyber_agent.extensions.validator import ExtensionValidator

    validation = ExtensionValidator().validate(manifest, raw=manifest.model_dump(mode="json"))
    return validation.errors


def load_official_extensions(
    directory: str | Path,
    *,
    registry: ExtensionRegistry | None = None,
    host: HostProfile | None = None,
    publisher: str = OFFICIAL_PUBLISHER,
) -> tuple[ExtensionRegistry, tuple[LoadReport, ...]]:
    """Discover + ingest official manifests with official trust.

    Trust comes from this loader's source class and publisher allowlist,
    never from the documents themselves."""
    from emo_cyber_agent.extensions.trust import OFFICIAL_PUBLISHERS

    target = Path(directory)
    if not target.is_dir():
        raise ExtensionError(ExtensionErrorCode.MANIFEST_MISSING, f"official directory missing: {target}")

    store = registry or ExtensionRegistry()
    host_profile = host or HostProfile()
    loader = ExtensionLoader(
        store,
        host=host_profile,
        official_publishers=tuple(sorted(OFFICIAL_PUBLISHERS)),
    )
    report = discover_directory(target, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    if not report.sources:
        raise ExtensionError(ExtensionErrorCode.MANIFEST_MISSING, f"no extensions discovered under {target}")
    reports = tuple(loader.ingest(source) for source in report.sources)
    return store, reports


# ---------------------------------------------------------------------------
# Read-only inspection surface (CLI / MCP thin projection)
# ---------------------------------------------------------------------------

#: The complete interactive surface. Reading and resolving only — the
#: adapter layer has no install, load, execute or trust-grant action.
READ_ACTIONS: tuple[str, ...] = ("list", "describe", "resolve", "check")

EXTENSION_PATH_ENV = "EMO_EXTENSION_PATH"
"""Host-configured directories scanned as external extensions (os.pathsep list)."""

USER_EXTENSIONS_DIR = Path("~/.config/emo-cyber-agent/extensions")
"""User extension directory. External content: never trusted by presence."""

PACKAGED_CATALOG = Path(__file__).resolve().parent.parent / "extensions_catalog"
"""Catalog shipped inside the package, when the host ships one."""


def extension_roots(
    *,
    extra: tuple[str | Path, ...] = (),
    include_packaged: bool = True,
    include_env: bool = True,
    include_user: bool = True,
) -> tuple[tuple[ExtensionSourceClass, Path], ...]:
    """Directories a read action may scan, each with its source class.

    Source class is decided by *where the directory came from*, never by
    what a document inside it claims about itself."""
    roots: list[tuple[ExtensionSourceClass, Path]] = []
    if include_packaged and PACKAGED_CATALOG.is_dir():
        roots.append((ExtensionSourceClass.OFFICIAL_EXTERNAL, PACKAGED_CATALOG))
    if include_env:
        for entry in str(os.environ.get(EXTENSION_PATH_ENV, "")).split(os.pathsep):
            if entry.strip():
                roots.append((ExtensionSourceClass.THIRD_PARTY, Path(entry).expanduser()))
    if include_user:
        user = USER_EXTENSIONS_DIR.expanduser()
        if user.is_dir():
            roots.append((ExtensionSourceClass.THIRD_PARTY, user))
    for item in extra:
        roots.append((ExtensionSourceClass.THIRD_PARTY, Path(item).expanduser()))
    return tuple(roots)


def build_read_registry(
    *,
    roots: tuple[tuple[ExtensionSourceClass, Path], ...] | None = None,
    extra: tuple[str | Path, ...] = (),
    host: HostProfile | None = None,
) -> tuple[ExtensionRegistry, tuple[LoadReport, ...], tuple[str, ...]]:
    """Metadata-only scan: discover + validate + trust + register.

    ``allow_code_load`` stays False, so nothing on this path can import
    an extension module. Quarantined and rejected content is recorded so
    it is *visible* without being resolvable."""
    selected = extension_roots(extra=extra) if roots is None else roots
    store = ExtensionRegistry(host=host)
    loader = ExtensionLoader(store, host=host, allow_code_load=False)
    reports: list[LoadReport] = []
    notes: list[str] = []
    for source_class, directory in selected:
        target = Path(directory)
        if not target.is_dir():
            notes.append(f"root-missing:{target}")
            continue
        report = discover_directory(target, source_class=source_class)
        for source in report.sources:
            reports.append(loader.ingest(source))
    return store, tuple(reports), tuple(notes)


def _describe_entry(store: ExtensionRegistry, entry: Any) -> dict[str, Any]:
    """One extension as data. Never projects an entry point target."""
    manifest = entry.manifest
    validation = store.validate(manifest, raw=manifest.model_dump(mode="json"))
    compatibility = store.check_compatibility(manifest.extension_id, manifest.version)
    body = dict(entry.summary())
    body.update(
        {
            "name": manifest.name,
            "description": manifest.description,
            "api_version": manifest.api_version,
            "license": manifest.license,
            "provides": {
                "declares": [value.value for value in manifest.provides.declares],
                "provides_feature": list(manifest.provides.provides_feature),
                "optional_feature": list(manifest.provides.optional_feature),
            },
            "requires": list(manifest.requires),
            "entrypoint": {
                "kind": manifest.entrypoint_metadata.kind.value,
                "contract": manifest.entrypoint_metadata.contract,
            },
            "resources": [
                {"resource_id": resource.resource_id, "kind": resource.kind.value, "path": resource.path}
                for resource in manifest.resources
            ],
            "security_profile": manifest.security_metadata.model_dump(mode="json"),
            "compatibility": compatibility.model_dump(mode="json"),
            "validation": {
                "valid": validation.valid,
                "errors": list(validation.errors),
                "warnings": list(validation.warnings),
                "digest_bound": validation.digest_bound,
            },
            "trust": entry.trust.model_dump(mode="json"),
            "provenance": entry.trust.evidence,
            "dataset_classification": manifest.dataset_classification.value,
        }
    )
    return body


def read_extensions(
    action: str,
    *,
    extension_id: str = "",
    version: str = "",
    provide: str = "",
    version_constraint: str = "",
    policy: str = "exact",
    extra_roots: tuple[str | Path, ...] = (),
    roots: tuple[tuple[ExtensionSourceClass, Path], ...] | None = None,
) -> dict[str, Any]:
    """Read-only projection used by the CLI and MCP adapters.

    Fail-closed: unknown actions, unknown ids and ambiguous versions
    raise ``ExtensionError`` instead of guessing, and no action here can
    install, load, upgrade, trust or execute anything."""
    if action not in READ_ACTIONS:
        raise ExtensionError(ExtensionErrorCode.QUERY_UNKNOWN, f"unsupported action: {action or '∅'}")

    store, reports, notes = build_read_registry(roots=roots, extra=extra_roots)
    scanned = tuple(str(directory) for _, directory in (roots if roots is not None else extension_roots(extra=extra_roots)))
    base: dict[str, Any] = {
        "action": action,
        "roots": scanned,
        "scanned": len(scanned),
        "discovered": len(reports),
        "registered": len(store.list()),
        "code_load": "disabled",
        "notes": list(notes),
    }

    if action == "list":
        entries = [_describe_entry(store, entry) for entry in store.list()]
        trust_counts: dict[str, int] = {}
        for entry in entries:
            trust_counts[entry["trust"]["state"]] = trust_counts.get(entry["trust"]["state"], 0) + 1
        base.update(
            {
                "count": len(entries),
                "trust_counts": dict(sorted(trust_counts.items())),
                "entries": sorted(entries, key=lambda item: (item["extension_id"], item["version"])),
                "conflicts": [
                    conflict.model_dump(mode="json") for conflict in store.provider_conflicts()
                ],
            }
        )
        return base

    if action == "resolve":
        if not extension_id and not provide:
            raise ExtensionError(
                ExtensionErrorCode.NOT_FOUND, "extension_id or provide is required for resolve"
            )
    elif not extension_id:
        raise ExtensionError(ExtensionErrorCode.NOT_FOUND, "extension_id is required for this action")

    def _unregistered_view() -> dict[str, Any] | None:
        """Rejected content never enters the registry; surface its report."""
        matches = [
            report
            for report in reports
            if report.extension_id == extension_id and (not version or report.version == version)
        ]
        if not matches:
            return None
        report = matches[0]
        return {
            "registered": False,
            "resolvable": False,
            "identity": f"{report.extension_id}@{report.version}",
            "trust": report.trust_state or "unknown",
            "lifecycle": report.trail[-1].value if report.trail else "discovered",
            "origin": report.origin,
            "reason": report.reason,
            "errors": list(report.validation.errors) if report.validation else [],
            "warnings": list(report.validation.warnings) if report.validation else [],
            "schema_valid": bool(report.validation.valid) if report.validation else False,
            "digest_bound": bool(report.validation.digest_bound) if report.validation else False,
            "compatible": bool(report.compatibility.compatible) if report.compatibility else False,
            "trail": [step.value for step in report.trail],
        }

    if action == "resolve":
        if policy not in ("exact", "highest_compatible"):
            raise ExtensionError(ExtensionErrorCode.QUERY_UNKNOWN, f"unsupported policy: {policy}")
        from emo_cyber_agent.extensions.resolver import ResolutionRequest
        from emo_cyber_agent.extensions.spec import VersionPolicy

        chosen_policy = (
            VersionPolicy.HIGHEST_COMPATIBLE if policy == "highest_compatible" else VersionPolicy.EXACT
        )
        request = ResolutionRequest(
            extension_id=extension_id,
            version_constraint=version_constraint,
            provide=provide,
            policy=chosen_policy,
        )
        base["resolution"] = store.resolve(request).model_dump(mode="json")
        return base

    if action == "check":
        try:
            entry = store.get(extension_id, version or None)
        except ExtensionError:
            fallback = _unregistered_view()
            if fallback is None:
                raise ExtensionError(
                    ExtensionErrorCode.NOT_FOUND,
                    f"extension not registered: {extension_id}@{version or '*'}",
                ) from None
            base["check"] = fallback
            return base
        body = _describe_entry(store, entry)
        base["check"] = {
            "identity": entry.identity,
            "schema_valid": body["validation"]["valid"],
            "digest_bound": body["validation"]["digest_bound"],
            "compatible": bool(body["compatibility"].get("compatible")),
            "trust": body["trust"]["state"],
            "lifecycle": body["lifecycle"],
            "registered": True,
            "resolvable": entry.trust.state.value in TRUSTED_STATES
            and entry.lifecycle.value not in ("quarantined", "rejected"),
            "trust_reasons": list(entry.trust.reasons),
            "errors": body["validation"]["errors"],
        }
        return base

    # action == "describe"
    matches = [entry for entry in store.list() if entry.extension_id == extension_id]
    if not matches:
        fallback = _unregistered_view()
        if fallback is None:
            raise ExtensionError(
                ExtensionErrorCode.NOT_FOUND,
                f"extension not registered: {extension_id}",
            )
        base["extension"] = fallback
        base["versions"] = []
        return base
    if version:
        matches = [entry for entry in matches if entry.version == version]
        if not matches:
            raise ExtensionError(
                ExtensionErrorCode.VERSION_NOT_FOUND,
                f"version not registered: {extension_id}@{version}",
            )
    base["extension"] = _describe_entry(store, matches[0])
    base["versions"] = store.versions(extension_id)
    return base
