"""ECA-T016 — E. Packaged resources tests.

Every official resource the product promises — skills, skill packs,
tasks, playbooks, report templates, tool packs, verification
strategies, verification adapters, threat methods, evaluation
metadata, schemas — loads from the INSTALLED package with the source
tree unreachable. Loaders are reused with an explicit directory; the
only release addition is resolving that directory from the wheel.
"""

from __future__ import annotations

import pytest

from conftest import run_installed

_CATALOG_COUNTS = (
    ("tools/packs/official", "toolpacks", 4),
    ("skills/packs/official", "skillpacks", 8),
    ("tasks/official", "tasks", 22),
    ("playbooks/official", "playbooks", 18),
    ("reports/official", "reports", 20),
    ("verification/official", "strategies", 24),
)

_LOADERS = {
    "toolpacks": (
        "from emo_cyber_agent.tools.packs.catalog import load_official_tool_packs as load",
        ".list()",
    ),
    "skillpacks": (
        "from emo_cyber_agent.skills.packs.catalog import load_official_packs as load",
        ".list()",
    ),
    "tasks": (
        "from emo_cyber_agent.tasks.library import load_official_registry as load",
        ".list()",
    ),
    "playbooks": (
        "from emo_cyber_agent.playbooks.library import load_official_registry as load",
        ".list()",
    ),
    "reports": (
        "from emo_cyber_agent.report_templates.library import load_official_registry as load",
        ".list()",
    ),
    "strategies": (
        "from emo_cyber_agent.verification.strategy import load_official_strategies as load",
        "",
    ),
}


@pytest.mark.parametrize(("subdir", "kind", "expected"), _CATALOG_COUNTS)
def test_official_catalog_loads_from_installed_package(venv, subdir, kind, expected):
    """One test per catalog: load from the wheel, assert the pinned count."""
    import_line, suffix = _LOADERS[kind]
    code = (
        "from emo_cyber_agent.core.resources import official_catalog_path, resource_origin;"
        f"{import_line};"
        "print(resource_origin());"
        f"print(len(load(official_catalog_path() / '{subdir}'){suffix}))"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code])
    origin, count = proc.stdout.strip().splitlines()
    assert origin == "packaged", "catalog must resolve from the installed wheel"
    assert int(count) == expected, f"{kind}: got {count}, expected {expected}"


def test_builtin_skills_resolve_from_installed_package(venv):
    code = (
        "from emo_cyber_agent.skills.builtin import load_builtin_registry;"
        "reg = load_builtin_registry();"
        "skills = reg.list() if hasattr(reg, 'list') else list(reg);"
        "print(len(skills))"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code])
    assert int(proc.stdout.strip().splitlines()[-1]) > 0


def test_verification_adapters_importable_from_installed_package(venv):
    code = (
        "from emo_cyber_agent.verification.adapters import MockVerificationAdapter;"
        "a = MockVerificationAdapter();"
        "print(type(a).__name__)"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code])
    assert "MockVerificationAdapter" in proc.stdout


def test_threat_methods_bootstrapped_from_installed_package(venv):
    code = (
        "from emo_cyber_agent.threat_modeling.methods import registered_methods, get_method;"
        "methods = registered_methods();"
        "print(','.join(methods));"
        "print(get_method('stride').method_id)"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code])
    lines = proc.stdout.strip().splitlines()
    assert "stride" in lines[0]
    assert lines[-1] == "stride"


def test_evaluation_schemas_available_from_installed_package(venv):
    code = (
        "from emo_cyber_agent.core.resources import load_schema_text;"
        "import json;"
        "names = ['evaluation-case', 'evaluation-dataset', 'evaluation-metric', 'evaluation-report', 'evaluation-run'];"
        "docs = [json.loads(load_schema_text(n)) for n in names];"
        "print(len(docs))"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code])
    assert proc.stdout.strip().splitlines()[-1] == "5"


def test_all_packaged_schemas_parse_from_installed_package(venv):
    code = (
        "from importlib import resources;"
        "import json;"
        "files = sorted(f for f in resources.files('emo_cyber_agent.data.schemas').iterdir() if f.suffix == '.json');"
        "docs = [json.loads(f.read_text(encoding='utf-8')) for f in files];"
        "print(len(docs))"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code])
    assert proc.stdout.strip().splitlines()[-1] == "36"
