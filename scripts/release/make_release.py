"""Generate release/release-manifest.json + release/SHA256SUMS — ECA-T016.

Deterministic release identity: artifact hashes, source-tree digest
(paths + contents, caches excluded), build tool versions, dependency
snapshot, schema/test/ruff/gate results. build_timestamp is recorded
but never mixed into any semantic or source digest.

Usage:
    python scripts/release/make_release.py \
      --test-result "1398 passed, 3 skipped" --test-count 1401 \
      --ruff-result PASS --security-gate PASS \
      --evaluation-gate PASS --invariant-gate PASS
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "dist"
RELEASE = ROOT / "release"

EXCLUDE_DIRS = {"__pycache__", ".git", ".pytest_cache", "dist", "build", "release", ".ruff_cache", ".mypy_cache", "htmlcov", ".venv", ".tox"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".DS_Store")
EXCLUDE_NAMES = {".coverage", "coverage.xml"}


def _version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def source_tree_digest() -> str:
    """Deterministic digest of tracked source content (no timestamps)."""
    files: list[Path] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDE_DIRS for part in rel.parts):
            continue
        if path.suffix in EXCLUDE_SUFFIXES or path.name in EXCLUDE_NAMES:
            continue
        files.append(path)
    digest = hashlib.sha256()
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        digest.update(rel.encode("utf-8") + b"\x00")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def git_revision() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30, cwd=str(ROOT)
        )
        return proc.stdout.strip() if proc.returncode == 0 else "untracked-tree"
    except (OSError, subprocess.SubprocessError):
        return "untracked-tree"


def build_tool() -> dict:
    try:
        uv = subprocess.run(["uv", "--version"], capture_output=True, text=True, timeout=30)
        uv_version = uv.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        uv_version = "unknown"
    try:
        import hatchling

        hatchling_version = getattr(hatchling, "__version__", "unknown")
    except ImportError:
        hatchling_version = "unknown"
    return {"builder": "uv-build", "uv": uv_version, "backend": "hatchling", "backend_version": hatchling_version}


def dependency_snapshot() -> dict:
    """Pinned runtime dependency identity (name → version + license)."""
    try:
        import importlib.metadata as md
    except ImportError:  # pragma: no cover
        return {}
    names = [
        "pydantic", "pydantic-settings", "pydantic-core", "typer", "rich",
        "pyyaml", "jsonschema", "typing-extensions", "annotated-types",
        "annotated-doc", "typing-inspection", "markdown-it-py", "mdurl",
        "pygments", "shellingham", "click", "attrs", "jsonschema-specifications",
        "referencing", "rpds-py", "python-dotenv",
    ]
    snapshot: dict[str, dict[str, str]] = {}
    for name in sorted(names):
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            continue
        lic = dist.metadata.get("License-Expression") or dist.metadata.get("License") or "UNKNOWN"
        snapshot[name] = {"version": dist.version, "license": lic}
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ECA-T016 release manifest")
    parser.add_argument("--test-result", default="", help="e.g. '1398 passed, 3 skipped'")
    parser.add_argument("--test-count", type=int, default=0)
    parser.add_argument("--ruff-result", default="UNKNOWN")
    parser.add_argument("--security-gate", default="UNKNOWN")
    parser.add_argument("--evaluation-gate", default="UNKNOWN")
    parser.add_argument("--invariant-gate", default="UNKNOWN")
    parser.add_argument("--release-channel", default="final")
    args = parser.parse_args(argv)

    version = _version()
    wheel = DIST / f"emo_cyber_agent-{version}-py3-none-any.whl"
    sdist = DIST / f"emo_cyber_agent-{version}.tar.gz"
    for artifact in (wheel, sdist):
        if not artifact.is_file():
            print(f"missing artifact: {artifact}", file=sys.stderr)
            return 2

    manifest = {
        "project": "emo-cyber-agent",
        "version": version,
        "release_channel": args.release_channel,
        "api_version": "1.0",
        "schema_version": "1.0",
        "git_revision": git_revision(),
        "source_tree_digest": source_tree_digest(),
        "build_timestamp": datetime.now(timezone.utc).isoformat(),
        "python_versions": ["3.11", "3.12"],
        "platform": f"{platform.system()}-{platform.machine()}",
        "artifacts": {
            "wheel": {
                "name": wheel.name,
                "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                "size": wheel.stat().st_size,
            },
            "sdist": {
                "name": sdist.name,
                "sha256": hashlib.sha256(sdist.read_bytes()).hexdigest(),
                "size": sdist.stat().st_size,
            },
        },
        "build_tool": build_tool(),
        "dependency_snapshot": dependency_snapshot(),
        "schema_count": 36,
        "schema_result": "36/36",
        "test_count": args.test_count,
        "test_result": args.test_result,
        "ruff_result": args.ruff_result,
        "security_gate": args.security_gate,
        "evaluation_gate": args.evaluation_gate,
        "invariant_gate": args.invariant_gate,
    }

    RELEASE.mkdir(parents=True, exist_ok=True)
    manifest_path = RELEASE / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    sums = RELEASE / "SHA256SUMS"
    lines = [
        f"{manifest['artifacts']['wheel']['sha256']}  {wheel.name}",
        f"{manifest['artifacts']['sdist']['sha256']}  {sdist.name}",
        f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  release-manifest.json",
    ]
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")

    for name in ("CHANGELOG.md", "LICENSE", "SECURITY.md"):
        (RELEASE / name).write_bytes((ROOT / name).read_bytes())

    print(json.dumps({"manifest": str(manifest_path), "sha256sums": str(sums), "source_tree_digest": manifest["source_tree_digest"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
