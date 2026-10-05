"""Shared fixtures for ECA-T016 release tests.

Release tests prove that previously validated behavior arrived intact in
the built artifact and works when installed. They run against dist/
artifacts inside fresh virtual environments — never against the source
tree — so a packaging, resource, or path defect fails here rather than
in the authoritative owner suites.

The venv fixtures are session-scoped: one base install and one install
with the ``mcp`` extra, plus a supported-Python matrix (3.11/3.12 per
``requires-python = ">=3.11"``).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "dist"

with (ROOT / "pyproject.toml").open("rb") as _fh:
    VERSION = tomllib.load(_fh)["project"]["version"]

WHEEL = DIST / f"emo_cyber_agent-{VERSION}-py3-none-any.whl"
SDIST = DIST / f"emo_cyber_agent-{VERSION}.tar.gz"


def _uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        pytest.fail("uv is required for release installation tests (https://docs.astral.sh/uv/)")
    return uv


def _make_venv(path: Path, *, python: str | None = None, extras: str = "") -> Path:
    """Create a fresh venv and pip-install the release wheel into it."""
    cmd = [_uv(), "venv", "--seed"]
    if python:
        cmd += ["--python", python]
    cmd += [str(path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        pytest.fail(f"venv creation failed:\n{proc.stdout[-1500:]}\n{proc.stderr[-1500:]}")
    target = f"{WHEEL}{extras}"
    proc = subprocess.run(
        [str(path / "bin" / "python"), "-m", "pip", "install", target],
        capture_output=True,
        text=True,
        timeout=900,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"pip install of release wheel failed:\nSTDOUT:\n{proc.stdout[-2000:]}\nSTDERR:\n{proc.stderr[-2000:]}"
        )
    return path


@pytest.fixture(scope="session")
def venv(tmp_path_factory):
    """Fresh venv with the release wheel installed (base dependencies)."""
    return _make_venv(tmp_path_factory.mktemp("release-venv"))


@pytest.fixture(scope="session")
def venv_mcp(tmp_path_factory):
    """Fresh venv with the release wheel plus the mcp extra."""
    return _make_venv(tmp_path_factory.mktemp("release-venv-mcp"), extras="[mcp]")


@pytest.fixture(scope="session")
def installed_python(venv) -> Path:
    """Interpreter of the clean base install."""
    return venv / "bin" / "python"


@pytest.fixture(scope="session")
def installed_python_mcp(venv_mcp) -> Path:
    """Interpreter of the clean install with the mcp extra."""
    return venv_mcp / "bin" / "python"


@pytest.fixture(scope="session")
def matrix_pythons(tmp_path_factory):
    """Supported Python versions per requires-python: 3.11 and 3.12."""
    pythons: dict[str, Path] = {}
    for version in ("3.11", "3.12"):
        proc = subprocess.run(
            [_uv(), "python", "install", version],
            capture_output=True,
            text=True,
            timeout=900,
        )
        if proc.returncode != 0:
            pytest.fail(f"uv python install {version} failed:\n{proc.stderr[-1500:]}")
        pythons[version] = _make_venv(
            tmp_path_factory.mktemp(f"release-venv-py{version}"), python=version
        )
    return pythons


def run_installed(
    python: Path,
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    env_extra: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run a command with the installed interpreter, source tree unreachable.

    cwd defaults to /tmp (outside the project) and PYTHONPATH is removed,
    so anything that resolves from the source tree fails loudly.
    """
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [str(python), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(cwd or Path("/tmp")),
        env=env,
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"installed run failed (exit {proc.returncode}): {' '.join(args)}\n"
            f"STDOUT:\n{proc.stdout[-2000:]}\nSTDERR:\n{proc.stderr[-2000:]}"
        )
    return proc


def run_console_script(
    venv: Path,
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    env_extra: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run the installed cyber-agent console script from outside the project."""
    return run_installed(
        venv / "bin" / "cyber-agent",
        args,
        cwd=cwd,
        timeout=timeout,
        env_extra=env_extra,
        check=check,
    )
