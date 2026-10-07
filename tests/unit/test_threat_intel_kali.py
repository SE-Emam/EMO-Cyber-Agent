"""Kali detector pack tests (offline, deterministic).

All 20 tools present with non-empty fields, pure-logic exposure
decisions, honest coverage gaps, determinism, and a no-probe AST
guard (no socket/subprocess, no network imports).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from emo_cyber_agent.threat_intel.kali_detectors import (
    TOOL_CATEGORIES,
    KaliToolDetectorPack,
    all_tool_names,
    coverage,
    detect_exposure,
    get_tool,
)

PACKAGE_DIR = Path(__file__).resolve().parents[2] / "src" / "emo_cyber_agent" / "threat_intel"
FORBIDDEN_IMPORTS = frozenset(
    {"socket", "urllib", "http", "requests", "httpx", "aiohttp", "urllib3",
     "ftplib", "smtplib", "telnetlib", "websockets", "subprocess"}
)

EXPECTED_TOOLS = frozenset(
    {"nmap", "metasploit-framework", "burpsuite", "sqlmap", "hydra", "john",
     "wireshark", "aircrack-ng", "nikto", "gobuster", "hashcat", "responder",
     "mimikatz", "empire", "bloodhound", "netcat", "socat", "theharvester",
     "maltego", "zaproxy"}
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


def test_no_probe_or_network_imports_in_package() -> None:
    sources = sorted(PACKAGE_DIR.glob("*.py"))
    assert len(sources) >= 5
    for path in sources:
        assert not (_imported_top_modules(path) & FORBIDDEN_IMPORTS), path.name
        text = path.read_text(encoding="utf-8")
        assert "socket.create_connection" not in text
        assert "subprocess." not in text or "no subprocess" in text.lower()


def test_all_twenty_tools_present() -> None:
    assert frozenset(all_tool_names()) == EXPECTED_TOOLS
    assert len(all_tool_names()) == 20


def test_tool_records_complete() -> None:
    for name in sorted(EXPECTED_TOOLS):
        tool = get_tool(name)
        assert tool.name == name
        assert tool.category in TOOL_CATEGORIES
        assert len(tool.abuses) >= 1
        assert len(tool.detects) >= 1
        assert all(a.strip() for a in tool.abuses)
        assert all(d.strip() for d in tool.detects)
        assert tool.guidance.strip()
        clone = type(tool).from_dict(tool.to_dict())
        assert clone.to_canonical_json() == tool.to_canonical_json()


def test_get_tool_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        get_tool("nmap-pro-max")


def test_hydra_without_rate_limit_is_exposed() -> None:
    report = detect_exposure("hydra", {"auth": True})
    assert report.exposed is True
    assert report.tool == "hydra"
    assert any("rate-limit" in r for r in report.reasons)
    assert report.guidance.strip()


def test_hydra_with_rate_limit_is_not_exposed() -> None:
    report = detect_exposure("hydra", {"auth": True, "rate_limit": True})
    assert report.exposed is False
    assert report.reasons == ("rate-limit-enforced",)


def test_hydra_without_auth_surface_is_not_exposed() -> None:
    report = detect_exposure("hydra", {})
    assert report.exposed is False


def test_nmap_open_ports_exposed() -> None:
    report = detect_exposure("nmap", {"open_ports": [22, 80]})
    assert report.exposed is True
    assert "open-ports-visible-to-scanning" in report.reasons
    quiet = detect_exposure("nmap", {})
    assert quiet.exposed is False


def test_john_secrets_exposed() -> None:
    assert detect_exposure("john", {"secrets": True}).exposed is True
    assert detect_exposure("john", {}).exposed is False
    assert detect_exposure("hashcat", {"secrets": ["hash1"]}).exposed is True


def test_nikto_missing_headers_exposed() -> None:
    report = detect_exposure("nikto", {"headers": {"server": "Apache/2.4"}})
    assert report.exposed is True
    assert any(r.startswith("missing-security-headers") for r in report.reasons)


def test_detect_rejects_unknown_tool() -> None:
    with pytest.raises(ValueError):
        detect_exposure("not-a-tool", {})


def test_detect_is_pure_and_deterministic() -> None:
    facts = {"auth": True, "open_ports": [443], "headers": {"server": "x"}}
    first = detect_exposure("burpsuite", facts)
    second = detect_exposure("burpsuite", dict(facts))
    assert first.to_canonical_json() == second.to_canonical_json()
    assert facts == {"auth": True, "open_ports": [443], "headers": {"server": "x"}}


def test_coverage_full_capabilities_no_gaps() -> None:
    caps: set[str] = set()
    for name in all_tool_names():
        caps.update(get_tool(name).detects)
    report = coverage(list(all_tool_names()), caps)
    assert report.gaps == ()
    assert len(report.covered) == 20
    assert report.coverage_ratio == pytest.approx(1.0)


def test_coverage_empty_capabilities_all_gaps() -> None:
    report = coverage(list(all_tool_names()), set())
    assert report.covered == ()
    assert frozenset(report.gaps) == EXPECTED_TOOLS
    assert report.coverage_ratio == pytest.approx(0.0)


def test_coverage_partial_is_honest() -> None:
    report = coverage(["hydra", "nmap", "john"], {"password-auth"})
    assert report.covered == ("hydra",)
    assert report.gaps == ("john", "nmap")
    assert report.coverage_ratio == pytest.approx(1 / 3)


def test_coverage_rejects_unknown_tool() -> None:
    with pytest.raises(ValueError):
        coverage(["hydra", "bogus-tool"], {"password-auth"})


def test_pack_facade() -> None:
    pack = KaliToolDetectorPack()
    assert len(pack.all_names()) == 20
    assert pack.get("sqlmap").category == "web"
    report = pack.detect_exposure("hydra", {"auth": True, "rate_limit": True})
    assert report.exposed is False
    cov = pack.coverage(["hydra"], set())
    assert cov.gaps == ("hydra",)
