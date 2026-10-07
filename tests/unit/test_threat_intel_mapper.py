"""ATT&CK technique mapper tests (offline, deterministic).

Known mappings, unknown-never-hallucinated, determinism, and static
table integrity, plus a no-network AST guard.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from emo_cyber_agent.threat_intel.technique_mapper import (
    TABLE_VERSION,
    TECHNIQUES,
    VALID_TACTICS,
    AttackTechniqueMapper,
    get_technique,
    map_finding,
    technique_known,
)

PACKAGE_DIR = Path(__file__).resolve().parents[2] / "src" / "emo_cyber_agent" / "threat_intel"
FORBIDDEN_IMPORTS = frozenset(
    {"socket", "urllib", "http", "requests", "httpx", "aiohttp", "urllib3",
     "ftplib", "smtplib", "telnetlib", "websockets", "subprocess"}
)

REQUIRED_IDS = frozenset(
    {"T1595", "T1190", "T1078", "T1003", "T1059", "T1021", "T1110", "T1552",
     "T1530", "T1204", "T1566", "T1048", "T1071", "T1499", "T1133", "T1098",
     "T1136", "T1090", "T1573", "T1557"}
)


def _imported_top_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found


def test_no_network_capable_imports_in_package() -> None:
    for path in sorted(PACKAGE_DIR.glob("*.py")):
        assert not (_imported_top_modules(path) & FORBIDDEN_IMPORTS), path.name


def test_table_covers_required_ids() -> None:
    ids = {t.id for t in TECHNIQUES}
    assert REQUIRED_IDS <= ids
    assert len(TECHNIQUES) >= 20


def test_table_integrity() -> None:
    assert re.match(r"^\d+\.\d+\.\d+$", TABLE_VERSION)
    ids = [t.id for t in TECHNIQUES]
    assert len(set(ids)) == len(ids)
    for tech in TECHNIQUES:
        assert tech.tactic in VALID_TACTICS
        assert tech.name.strip()
        assert tech.description.strip()
        assert tech.detection_guidance.strip()
        assert len(tech.kali_tools) >= 1
        assert all(tool.strip() for tool in tech.kali_tools)
        assert re.match(r"^T\d{4}(\.\d{3})?$", tech.id)
        for cwe in tech.cwe_refs:
            assert re.match(r"^CWE-\d+$", cwe)


def test_known_cwe_mapping_brute_force() -> None:
    hits = map_finding(cwe="CWE-307")
    assert hits
    assert hits[0].technique_id == "T1110"
    assert hits[0].basis == "cwe"


def test_cwe_normalizes_bare_digits() -> None:
    hits = map_finding(cwe="307")
    assert [h.technique_id for h in hits] == [h.technique_id for h in map_finding(cwe="CWE-307")]


def test_cwe_mapping_shared_cwe() -> None:
    ids = {h.technique_id for h in map_finding(cwe="CWE-798")}
    assert {"T1078", "T1552"} <= ids


def test_keyword_mapping() -> None:
    hits = map_finding(keywords=("brute", "password"))
    ids = [h.technique_id for h in hits]
    assert "T1110" in ids
    assert all(h.basis == "keyword" for h in hits)


def test_category_mapping() -> None:
    hits = map_finding(category="CREDENTIAL_EXPOSURE")
    assert hits
    assert all(technique_known(h.technique_id) for h in hits)


def test_cwe_outranks_keyword() -> None:
    hits = map_finding(cwe="CWE-307", keywords=("cloud", "storage"))
    assert hits
    assert hits[0].basis == "cwe"
    assert hits[0].technique_id == "T1110"


def test_unknown_signals_map_to_empty_never_hallucinated() -> None:
    assert map_finding(cwe="CWE-9999") == []
    assert map_finding(keywords=("zzqxjkw",)) == []
    assert map_finding() == []
    assert map_finding(category="NOT_A_REAL_CATEGORY", cwe="CWE-9999", keywords=("zzqxjkw",)) == []


def test_all_returned_ids_exist_in_table() -> None:
    probes = [
        {"cwe": "CWE-200"},
        {"cwe": "CWE-300"},
        {"keywords": ("password", "hash")},
        {"category": "SENSITIVE_DATA_EXFILTRATION"},
        {"keywords": ("scan", "network")},
        {"cwe": "CWE-78", "keywords": ("shell",)},
    ]
    for probe in probes:
        for hit in map_finding(**probe):
            assert technique_known(hit.technique_id), hit.technique_id


def test_technique_known_validator() -> None:
    assert technique_known("T1110") is True
    assert technique_known("t1110") is True
    assert technique_known("T9999") is False
    assert technique_known("") is False
    assert technique_known("not-a-technique") is False


def test_get_technique_roundtrip() -> None:
    tech = get_technique("T1595")
    assert tech.name == "Active Scanning"
    assert tech.tactic == "Reconnaissance"
    clone = type(tech).from_dict(tech.to_dict())
    assert clone.to_canonical_json() == tech.to_canonical_json()


def test_get_technique_rejects_unknown() -> None:
    try:
        get_technique("T9999")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_mapping_deterministic() -> None:
    probe = {"category": "CREDENTIAL_EXPOSURE", "cwe": "CWE-307", "keywords": ("password",)}
    first = [h.to_canonical_json() for h in map_finding(**probe)]
    second = [h.to_canonical_json() for h in map_finding(**probe)]
    assert first == second


def test_mapper_facade() -> None:
    mapper = AttackTechniqueMapper()
    assert "T1110" in mapper.all_ids()
    assert mapper.known("T1059") is True
    assert mapper.get("T1059").tactic == "Execution"
    assert mapper.map_finding(cwe="CWE-307")[0].technique_id == "T1110"
