"""ECA-T016 — B. Artifact tests.

Wheel and sdist contents are complete and clean: required wheel files,
all schemas/policies/official catalogs packaged, valid RECORD hashes,
no forbidden files, no secrets (the only credential-shaped strings in
the sdist are the three synthetic redaction fixtures that assert
redaction works), and required legal/docs files present.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path


from conftest import ROOT, SDIST, VERSION, WHEEL

FORBIDDEN_NAMES = (
    ".env",
    "__pycache__",
    ".pyc",
    ".pyo",
    "PLACEHOLDER",
    ".DS_Store",
    "id_rsa",
    ".pem",
    ".key",
)

SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
)

# Synthetic credential-shaped fixtures that exist to prove redaction.
# They are test data, not secrets; no other hits are allowed.
KNOWN_SYNTHETIC_FIXTURES = {
    "tests/unit/test_evaluation_oracles_metrics_gates.py",
    "tests/unit/test_repository.py",
    "tests/unit/test_verification_regression.py",
    # POST-T018: redaction-test inputs (AWS-documented AKIA...EXAMPLE +
    # bare PRIVATE KEY header), asserted redacted by the tests themselves.
    "tests/unit/subagent/test_result_firewall.py",
}


def _wheel_names() -> list[str]:
    with zipfile.ZipFile(WHEEL) as z:
        return z.namelist()


def _sdist_names() -> list[str]:
    with tarfile.open(SDIST) as t:
        return t.getnames()


def test_wheel_contains_required_files():
    names = _wheel_names()
    from conftest import DIST_INFO

    dist_info = DIST_INFO
    for required in ("METADATA", "WHEEL", "RECORD", "entry_points.txt"):
        assert f"{dist_info}/{required}" in names, required
    assert f"{dist_info}/licenses/LICENSE" in names
    # package code + packaged resources
    assert "emo_cyber_agent/__init__.py" in names
    assert "emo_cyber_agent/cli/main.py" in names
    assert "emo_cyber_agent/mcp/server.py" in names
    assert "emo_cyber_agent/extensions/__init__.py" in names


def test_wheel_contains_all_schemas_policies_and_official_catalog():
    names = _wheel_names()
    schemas = [n for n in names if n.startswith("emo_cyber_agent/data/schemas/") and n.endswith(".json")]
    source_schemas = sorted(p.name for p in (ROOT / "docs" / "schemas").glob("*.json"))
    assert len(schemas) == 36, f"wheel ships {len(schemas)} schemas, expected 36"
    assert sorted(Path(n).name for n in schemas) == source_schemas
    policies = [n for n in names if n.startswith("emo_cyber_agent/data/policies/")]
    assert len(policies) == 2, policies
    official = [n for n in names if n.startswith("emo_cyber_agent/data/official/")]
    assert len(official) >= 90, f"official catalog incomplete: {len(official)} files"
    # every official domain the loaders resolve is packaged
    for domain in ("skills/packs/official", "tasks/official", "playbooks/official", "reports/official", "tools/packs/official", "verification/official", "threat-modeling/official"):
        assert any(f"emo_cyber_agent/data/official/{domain}/" in n for n in names), domain


def test_wheel_record_hashes_are_valid():
    with zipfile.ZipFile(WHEEL) as z:
        bad = []
        from conftest import DIST_INFO

        for row in csv.reader(z.read(f"{DIST_INFO}/RECORD").decode().splitlines()):
            if len(row) < 3 or not row[1]:
                continue
            path, expected_hash, _size = row[0], row[1], row[2]
            algo, expected = expected_hash.split("=", 1)
            digest = base64.urlsafe_b64encode(hashlib.new(algo, z.read(path)).digest()).rstrip(b"=").decode()
            if digest != expected:
                bad.append(path)
        assert not bad, f"RECORD hash mismatches: {bad}"


def test_artifacts_contain_no_forbidden_files():
    for name in _wheel_names() + _sdist_names():
        assert not any(token in name for token in FORBIDDEN_NAMES), name


def test_artifacts_contain_no_secrets():
    """Scan wheel + sdist contents. Only known synthetic redaction fixtures may match."""
    hits: list[str] = []
    with zipfile.ZipFile(WHEEL) as z:
        for name in z.namelist():
            if name.endswith((".py", ".json", ".yaml", ".md", ".toml", ".txt")):
                text = z.read(name).decode("utf-8", errors="ignore")
                if any(p.search(text) for p in SECRET_PATTERNS):
                    hits.append(f"wheel:{name}")
    with tarfile.open(SDIST) as t:
        for member in t.getmembers():
            if not member.isfile() or member.size > 500_000:
                continue
            if not member.name.endswith((".py", ".json", ".yaml", ".md", ".toml", ".txt")):
                continue
            handle = t.extractfile(member)
            if handle is None:
                continue
            text = handle.read().decode("utf-8", errors="ignore")
            if any(p.search(text) for p in SECRET_PATTERNS):
                hits.append(f"sdist:{member.name}")
    def _rel(hit: str) -> str:
        kind, name = hit.split(":", 1)
        # sdist members carry the top-level "<name>-<version>/" prefix
        parts = name.split("/", 1)
        return parts[1] if len(parts) == 2 and kind == "sdist" else name

    unexpected = [h for h in hits if _rel(h) not in KNOWN_SYNTHETIC_FIXTURES]
    assert not unexpected, f"unexpected secret-shaped content: {unexpected}"
    assert hits, "expected the three known synthetic redaction fixtures to be present"


def test_license_changelog_security_docs_present():
    assert (ROOT / "LICENSE").exists()
    assert "Apache License" in (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert not (ROOT / "LICENSE-PLACEHOLDER.md").exists()
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "0.1.0" in changelog
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8").lower()
    assert "report" in security and "vulnerab" in security
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8").lower()
    assert "test" in contributing


def test_development_report_inventory_complete():
    dev = ROOT / "reports" / "development"
    assert (dev / "00-project-reconnaissance.md").exists()
    for n in range(1, 17):
        matches = list(dev.glob(f"ECA-T{n:03d}*.md"))
        if n == 15:
            matches = matches or list((ROOT / "reports" / "security").glob("ECA-T015*.md"))
        assert matches, f"missing report for ECA-T{n:03d}"
    sec = ROOT / "reports" / "security"
    assert (sec / "00-security-baseline.md").exists()


def test_packaged_schemas_match_source_schemas():
    """source schemas = packaged schemas (approved release manifest rule)."""
    with zipfile.ZipFile(WHEEL) as z:
        for source in sorted((ROOT / "docs" / "schemas").glob("*.json")):
            packaged = z.read(f"emo_cyber_agent/data/schemas/{source.name}").decode("utf-8")
            assert json.loads(packaged) == json.loads(source.read_text(encoding="utf-8")), source.name
