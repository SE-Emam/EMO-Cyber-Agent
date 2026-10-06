"""ECA-T016 — C. Clean installation tests.

pip install into a fresh venv, pipx install, and the supported-Python
matrix (3.11/3.12 per requires-python). Every check runs from /tmp with
PYTHONPATH removed, so the source tree is unreachable: anything that
only works from a checkout fails here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


from conftest import ROOT, VERSION, WHEEL, run_installed


def test_pip_install_into_fresh_venv_succeeds(venv):
    """The venv fixture is the proof: pip install of the wheel succeeded."""
    proc = run_installed(venv / "bin" / "python", ["-m", "pip", "show", "emo-cyber"])
    assert "Name: emo-cyber" in proc.stdout
    assert f"Version: {VERSION}" in proc.stdout


def test_import_succeeds_from_installed_package(venv):
    proc = run_installed(
        venv / "bin" / "python",
        ["-c", "import emo_cyber_agent, sys; print(emo_cyber_agent.__file__); print(emo_cyber_agent.__version__)"],
    )
    assert proc.stdout.strip().splitlines()[-1] == VERSION
    package_file = proc.stdout.strip().splitlines()[0]
    assert str(venv) in package_file, f"package resolved from {package_file}, not the venv"
    assert str(ROOT) not in package_file, "package resolved from the source tree, not the install"


def test_resources_resolve_from_installed_package(venv):
    """Installed wheel + source tree unavailable -> resources still resolve."""
    code = (
        "from emo_cyber_agent.core.resources import load_schema_text, load_policy_text, "
        "official_catalog_path, resource_origin, validate_packaged_schemas;"
        "print(resource_origin());"
        "print(len(validate_packaged_schemas()));"
        "print(bool(load_schema_text('finding')));"
        "print(bool(load_policy_text('verify')));"
        "print(official_catalog_path().is_dir())"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code])
    lines = proc.stdout.strip().splitlines()
    assert lines[0] == "packaged", "resources must resolve from the installed wheel"
    assert lines[1] == "5"
    assert lines[2] == "True"
    assert lines[3] == "True"
    assert lines[4] == "True"


def test_official_catalog_loaders_resolve_from_installed_package(venv):
    """The official catalogs load through their existing loaders, from the wheel."""
    code = (
        "from emo_cyber_agent.core.resources import official_catalog_path;"
        "from emo_cyber_agent.tools.packs.catalog import load_official_tool_packs;"
        "from emo_cyber_agent.skills.packs.catalog import load_official_packs;"
        "from emo_cyber_agent.tasks.library import load_official_registry as tasks;"
        "from emo_cyber_agent.playbooks.library import load_official_registry as playbooks;"
        "from emo_cyber_agent.report_templates.library import load_official_registry as reports;"
        "from emo_cyber_agent.verification.strategy import load_official_strategies;"
        "root = official_catalog_path();"
        "print(len(load_official_tool_packs(root / 'tools' / 'packs' / 'official').list()));"
        "print(len(load_official_packs(root / 'skills' / 'packs' / 'official').list()));"
        "print(len(tasks(root / 'tasks' / 'official').list()));"
        "print(len(playbooks(root / 'playbooks' / 'official').list()));"
        "print(len(reports(root / 'reports' / 'official').list()));"
        "print(len(load_official_strategies(root / 'verification' / 'official')))"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code])
    counts = [int(line) for line in proc.stdout.strip().splitlines()]
    assert counts == [4, 8, 22, 18, 20, 24], counts


def test_python_version_matrix(matrix_pythons):
    """Wheel installs and runs on every supported Python version."""
    for version, venv in matrix_pythons.items():
        proc = run_installed(
            venv / "bin" / "python",
            ["-c", f"import emo_cyber_agent; print(emo_cyber_agent.__version__); print('{version}')"],
        )
        assert proc.stdout.strip().splitlines()[-1] == version
        assert VERSION in proc.stdout


def test_pipx_install_and_run_from_outside_project(tmp_path):
    """pipx creates an isolated venv; cyber-agent must work from /tmp."""
    pipx = shutil.which("pipx")
    if pipx is None:
        pipx = str(Path.home() / ".local" / "bin" / "pipx")
    assert Path(pipx).is_file(), "pipx is required for the release gate"
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [pipx, "install", str(WHEEL)],
        capture_output=True,
        text=True,
        timeout=900,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    try:
        listed = subprocess.run(
            [pipx, "list", "--short"],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        assert "emo-cyber" in listed.stdout
        # run from /tmp — outside the project directory
        run = subprocess.run(
            ["cyber-agent", "--version"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd="/tmp",
            env=env,
        )
        assert run.returncode == 0, run.stderr[-1000:]
        assert VERSION in run.stdout
        doctor = subprocess.run(
            ["cyber-agent", "doctor", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd="/tmp",
            env=env,
        )
        assert doctor.returncode == 0, doctor.stderr[-1000:]
        assert json.loads(doctor.stdout)["status"] == "ok"
    finally:
        subprocess.run([pipx, "uninstall", "emo-cyber"], capture_output=True, timeout=300, env=env)
