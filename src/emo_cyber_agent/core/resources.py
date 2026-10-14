"""Packaged resource loading — ECA-T016.

Single source of truth stays in docs/schemas and docs/policies; the wheel
ships copies under emo_cyber_agent/data/* (see force-include in
pyproject.toml). This loader resolves packaged resources first
(importlib.resources — works from any install) and falls back to the
source tree (development checkouts). No ../../relative/path assumptions
anywhere else in the codebase.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Any

SCHEMA_NAMES = ("audit-request", "audit-result", "finding", "tool-spec", "report")
POLICY_NAMES = ("default-read-only", "verify")


def _source_tree_root() -> Path | None:
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        if (parent / "pyproject.toml").exists():
            return parent
    return None


def load_schema_text(name: str) -> str:
    """Return the canonical JSON text of a schema by short name."""
    filename = f"{name}.schema.json"
    try:
        packaged = resources.files("emo_cyber_agent.data.schemas").joinpath(filename)
        if packaged.is_file():
            return packaged.read_text(encoding="utf-8")
    except (ModuleNotFoundError, FileNotFoundError, AttributeError):
        pass
    root = _source_tree_root()
    if root is not None:
        candidate = root / "docs" / "schemas" / filename
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise FileNotFoundError(f"schema not available: {filename}")


def load_policy_text(name: str) -> str:
    filename = f"{name}.yaml"
    try:
        packaged = resources.files("emo_cyber_agent.data.policies").joinpath(filename)
        if packaged.is_file():
            return packaged.read_text(encoding="utf-8")
    except (ModuleNotFoundError, FileNotFoundError, AttributeError):
        pass
    root = _source_tree_root()
    if root is not None:
        candidate = root / "docs" / "policies" / filename
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise FileNotFoundError(f"policy not available: {filename}")


@contextmanager
def gitleaks_policy_paths() -> Iterator[tuple[Path, Path]]:
    """Yield packaged, trusted Gitleaks configuration and empty ignore file.

    Keeping these paths outside the target repository prevents repo-controlled
    config and ignore files from silently weakening a mandatory scan.
    """
    names = ("gitleaks-default.toml", "empty-gitleaksignore")
    try:
        package = resources.files("emo_cyber_agent.data.policies")
        config = package.joinpath(names[0])
        ignore = package.joinpath(names[1])
        if config.is_file() and ignore.is_file():
            with resources.as_file(config) as config_path, resources.as_file(ignore) as ignore_path:
                yield Path(config_path), Path(ignore_path)
            return
    except (ModuleNotFoundError, FileNotFoundError, AttributeError):
        pass
    root = _source_tree_root()
    if root is None:
        raise FileNotFoundError("trusted Gitleaks policy resources are unavailable")
    config_path, ignore_path = (root / "docs" / "policies" / name for name in names)
    if not config_path.is_file() or not ignore_path.is_file():
        raise FileNotFoundError("trusted Gitleaks policy resources are unavailable")
    yield config_path, ignore_path


def validate_packaged_schemas() -> dict[str, str]:
    """Parse every known schema; returns name → OK. Raises on any failure."""
    results: dict[str, str] = {}
    for name in SCHEMA_NAMES:
        json.loads(load_schema_text(name))
        results[name] = "OK"
    return results


def resource_origin() -> str:
    """Where resources resolved from: packaged data vs source tree."""
    try:
        packaged = resources.files("emo_cyber_agent.data.schemas").joinpath("finding.schema.json")
        if packaged.is_file():
            return "packaged"
    except (ModuleNotFoundError, FileNotFoundError, AttributeError):
        pass
    return "source-tree" if _source_tree_root() is not None else "missing"


def official_catalog_path() -> Path:
    """Packaged official catalog directory (skills/packs/tasks/playbooks/
    report templates/tool packs/verification strategies/threat models).

    Resolves from the installed wheel first and falls back to the source
    tree (development checkouts). The directory contains YAML content only;
    loading it never imports or executes anything.

    The path is anchored at this module's own package directory (not
    importlib.resources traversables), so callers always receive a real
    filesystem path that outlives the call.
    """
    candidate = Path(__file__).resolve().parent.parent / "data" / "official"
    if candidate.is_dir():
        return candidate
    root = _source_tree_root()
    if root is not None:
        candidate = root / "templates"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        "official catalog not available: templates/official missing from package and source tree"
    )


def load_config_schema() -> dict[str, Any]:
    return {"model": "", "provider_endpoint": ""}
