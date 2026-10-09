"""ECA-T016 — A. Build tests.

Wheel and sdist exist, metadata is valid per current Core Metadata
semantics (2.6: SPDX license expression, license-files, project URLs),
the build reproduces from the current tree, and one version is consistent
everywhere. No security behavior is re-tested here.
"""

from __future__ import annotations

import email.parser
import email.message
import subprocess
import tarfile
import zipfile


from conftest import DIST_INFO, ROOT, SDIST, VERSION, WHEEL, _uv


def _metadata() -> email.message.Message:
    with zipfile.ZipFile(WHEEL) as z:
        return email.parser.Parser().parsestr(
            z.read(f"{DIST_INFO}/METADATA").decode()
        )


def test_wheel_and_sdist_exist():
    assert WHEEL.is_file(), f"missing wheel: {WHEEL}"
    assert SDIST.is_file(), f"missing sdist: {SDIST}"
    assert WHEEL.stat().st_size > 10_000
    assert SDIST.stat().st_size > 10_000


def test_metadata_valid_per_core_metadata_2_6():
    meta = _metadata()
    assert meta["Name"] == "emo-cyber"
    assert meta["Version"] == VERSION
    assert meta["Requires-Python"] == ">=3.11"
    # PEP 639 SPDX expression + license file (Core Metadata 2.4+ semantics)
    assert meta["License-Expression"] == "Apache-2.0"
    assert "License-File: LICENSE" in meta.get_all("License-File", []) or meta["License-File"] == "LICENSE"
    # project.urls present
    urls = meta.get_all("Project-URL", [])
    assert any(url.startswith("Homepage,") for url in urls), urls
    assert any(url.startswith("Repository,") for url in urls), urls
    # direct dependencies bounded below+above, no URL/git sources
    direct = [
        item
        for item in meta.get_all("Requires-Dist", [])
        if "extra ==" not in item
    ]
    assert len(direct) == 6, direct
    for dep in direct:
        assert ">=" in dep and "<" in dep, dep
        assert not dep.startswith(("git+", "http")), dep
    # optional extras stay optional
    extras = {item.split("extra ==")[1].strip().strip("'\"") for item in meta.get_all("Requires-Dist", []) if "extra ==" in item}
    assert {"mcp", "http", "dev", "all"} <= extras, extras
    # license classifier consistent with SPDX expression
    assert "License :: OSI Approved :: Apache Software License" in meta.get_all("Classifier", [])
    # console script entry point
    with zipfile.ZipFile(WHEEL) as z:
        entry_points = z.read(f"{DIST_INFO}/entry_points.txt").decode()
    assert "cyber-agent = emo_cyber_agent.cli.main:app" in entry_points


def test_version_consistency_across_contracts():
    import emo_cyber_agent as pkg
    from emo_cyber_agent.core.reporting import EMO_VERSION, REPORT_VERSION
    from emo_cyber_agent.mcp import protocol as mcp_proto
    from emo_cyber_agent.mcp.tools import TOOLS

    assert pkg.__version__ == VERSION == "0.2.1"
    assert EMO_VERSION == pkg.__version__
    assert mcp_proto.SERVER_VERSION == pkg.__version__
    assert len(TOOLS) == 7  # +cyber_threat_intel post-0.1.0 (tag v0.1.0 pins 6)
    # independent versions stay independent (never implicitly tied)
    from emo_cyber_agent.core import policy as policy_mod
    from emo_cyber_agent.core.correlation import CORRELATION_RULES_VERSION
    from emo_cyber_agent.core.findings import CLASSIFICATION_VERSION

    assert policy_mod.POLICY_VERSION == "eca-t007-v1"
    assert CORRELATION_RULES_VERSION == "corr-v1"
    assert CLASSIFICATION_VERSION == "cls-v1"
    assert REPORT_VERSION == "1.0"
    assert {policy_mod.POLICY_VERSION, CORRELATION_RULES_VERSION, CLASSIFICATION_VERSION, REPORT_VERSION}.isdisjoint({pkg.__version__})


def test_build_reproduces_from_current_tree(tmp_path):
    """Clean isolated build of wheel + sdist from the current tree."""
    out = tmp_path / "dist"
    proc = subprocess.run(
        [_uv(), "build", "--out-dir", str(out)],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert (out / WHEEL.name).is_file()
    assert (out / SDIST.name).is_file()
    # wheel tag appropriate for a pure-Python package
    with zipfile.ZipFile(out / WHEEL.name) as z:
        wheel_meta = z.read(f"{DIST_INFO}/WHEEL").decode()
    assert "Root-Is-Purelib: true" in wheel_meta
    assert "Tag: py3-none-any" in wheel_meta


def test_sdist_is_a_complete_source_distribution():
    with tarfile.open(SDIST) as t:
        names = t.getnames()
    prefixes = {n.split("/")[1] for n in names if n.count("/") >= 1 and len(n.split("/")) > 1}
    for required in ("src", "docs", "tests", "templates", "examples", "scripts", "reports"):
        assert required in prefixes, f"sdist missing {required}/"
    for required in ("LICENSE", "README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md", "pyproject.toml", "Makefile"):
        assert any(n.endswith(required) for n in names), f"sdist missing {required}"
