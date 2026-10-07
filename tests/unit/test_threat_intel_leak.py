"""Threat-intel leak monitor tests (offline, deterministic).

Builders, parsers, digest-not-raw, triage branches, default-refuse
fetchers, frozen-model shape, and a no-network AST guard.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

import pytest

from emo_cyber_agent.threat_intel.leak_monitor import (
    HIBP_API_BASE,
    THREATFOX_API_URL,
    DarkLeakMonitor,
    LeakFinding,
    hibp_breach_request,
    parse_hibp_response,
    parse_threatfox_response,
    threatfox_ioc_request,
    triage,
)

PACKAGE_DIR = Path(__file__).resolve().parents[2] / "src" / "emo_cyber_agent" / "threat_intel"
FORBIDDEN_IMPORTS = frozenset(
    {"socket", "urllib", "http", "requests", "httpx", "aiohttp", "urllib3",
     "ftplib", "smtplib", "telnetlib", "websockets", "subprocess"}
)


def _package_sources() -> list[Path]:
    return sorted(PACKAGE_DIR.glob("*.py"))


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
    sources = _package_sources()
    assert len(sources) >= 5
    for path in sources:
        assert not (_imported_top_modules(path) & FORBIDDEN_IMPORTS), path.name


def test_hibp_request_shape() -> None:
    req = hibp_breach_request("user@example.com")
    assert req["method"] == "GET"
    assert req["endpoint"] == f"{HIBP_API_BASE}/breachedaccount/user@example.com"
    assert set(req) == {"endpoint", "method", "params"}
    assert req["params"]["truncateResponse"] is True


def test_hibp_request_rejects_blank() -> None:
    with pytest.raises(ValueError):
        hibp_breach_request("  ")


def test_threatfox_request_shape() -> None:
    req = threatfox_ioc_request("44d88612fea8a8f36de82e1278abb02f", "hash")
    assert req["method"] == "POST"
    assert req["endpoint"] == THREATFOX_API_URL
    assert set(req) == {"endpoint", "method", "params"}
    assert req["params"]["query"] == "search_ioc"


def test_threatfox_request_rejects_bad_type() -> None:
    with pytest.raises(ValueError):
        threatfox_ioc_request("1.2.3.4", "carrier-pigeon")


HIBP_FIXTURE = {
    "account": "user@example.com",
    "breaches": [
        {"Name": "ExampleBreach", "BreachDate": "2021-05-01", "IsVerified": True},
        {"Name": "OtherBreach", "BreachDate": "2022-01-15", "IsVerified": False},
    ],
}

THREATFOX_FIXTURE = {
    "query_status": "ok",
    "data": [
        {"ioc": "1.2.3.4", "threat_type": "botnet_cc", "first_seen": "2023-01-01",
         "confidence_level": 90},
        {"ioc": "evil.example.com", "malware_printable": "Emotet", "first_seen": "2023-02-02",
         "confidence_level": "low"},
    ],
}


def test_parse_hibp_digests_identifier_never_raw() -> None:
    findings = parse_hibp_response(HIBP_FIXTURE)
    assert len(findings) == 2
    expected = hashlib.sha256(b"user@example.com").hexdigest()
    for finding in findings:
        assert finding.source == "hibp"
        assert finding.identifier_digest == expected
        assert re.match(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$", finding.finding_id)
    blob = " ".join(f.to_canonical_json() for f in findings)
    assert "user@example.com" not in blob
    assert "raw_secret" not in blob
    for finding in findings:
        assert "raw_secret" not in finding.to_dict()


def test_parse_hibp_confidence_hint() -> None:
    findings = parse_hibp_response(HIBP_FIXTURE)
    assert findings[0].confidence == 0.9
    assert findings[1].confidence == 0.6
    assert findings[0].name == "ExampleBreach"
    assert findings[0].date == "2021-05-01"


def test_parse_threatfox_digests_ioc_never_raw() -> None:
    findings = parse_threatfox_response(THREATFOX_FIXTURE)
    assert len(findings) == 2
    assert findings[0].identifier_digest == hashlib.sha256(b"1.2.3.4").hexdigest()
    assert findings[1].identifier_digest == hashlib.sha256(b"evil.example.com").hexdigest()
    blob = " ".join(f.to_canonical_json() for f in findings)
    assert "1.2.3.4" not in blob
    assert "evil.example.com" not in blob
    assert findings[0].confidence == pytest.approx(0.9)
    assert findings[1].confidence == pytest.approx(0.3)


def test_parse_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_hibp_response("not-a-payload")
    with pytest.raises(ValueError):
        parse_hibp_response({"account": "a@b.c", "breaches": "nope"})
    with pytest.raises(ValueError):
        parse_threatfox_response({"data": [{"nope": 1}]})
    with pytest.raises(ValueError):
        parse_threatfox_response(42)


def test_triage_relevant_unrelated_quarantine() -> None:
    findings = parse_hibp_response(HIBP_FIXTURE)
    digest = findings[0].identifier_digest
    assert triage(findings[0], {digest}) == "RELEVANT"
    assert triage(findings[0], {"0" * 64}) == "UNRELATED"
    assert triage({"garbage": True}, {digest}) == "QUARANTINE"
    assert triage(None, {digest}) == "QUARANTINE"
    assert triage("nonsense", {digest}) == "QUARANTINE"


def test_triage_accepts_dict_form_and_ignores_bad_scope() -> None:
    findings = parse_threatfox_response(THREATFOX_FIXTURE)
    payload = findings[0].to_dict()
    assert triage(payload, [findings[0].identifier_digest]) == "RELEVANT"
    assert triage(payload, ["not-a-digest"]) == "UNRELATED"


def test_finding_model_frozen_and_forbidding() -> None:
    finding = parse_hibp_response(HIBP_FIXTURE)[0]
    with pytest.raises(Exception):
        finding.name = "mutated"  # type: ignore[misc]
    with pytest.raises(Exception):
        LeakFinding.model_validate({**finding.to_dict(), "raw_secret": "x"})
    clone = LeakFinding.from_dict(finding.to_dict())
    assert clone.to_canonical_json() == finding.to_canonical_json()


def test_parse_deterministic() -> None:
    first = [f.to_canonical_json() for f in parse_hibp_response(HIBP_FIXTURE)]
    second = [f.to_canonical_json() for f in parse_hibp_response(HIBP_FIXTURE)]
    assert first == second


def test_monitor_refuses_without_fetcher() -> None:
    monitor = DarkLeakMonitor()
    assert monitor.has_hibp_fetcher is False
    with pytest.raises(RuntimeError):
        monitor.fetch_hibp(monitor.build_hibp_request("a@b.c"))
    with pytest.raises(RuntimeError):
        monitor.fetch_threatfox(monitor.build_threatfox_request("1.2.3.4", "ip"))
    with pytest.raises(RuntimeError):
        monitor.check_account("a@b.c")


def test_monitor_uses_injected_fetchers() -> None:
    monitor = DarkLeakMonitor(
        hibp_fetcher=lambda req: HIBP_FIXTURE,
        threatfox_fetcher=lambda req: THREATFOX_FIXTURE,
    )
    req, findings = monitor.check_account("user@example.com")
    assert req["method"] == "GET"
    assert len(findings) == 2
    assert monitor.triage(findings[0], {findings[0].identifier_digest}) == "RELEVANT"
    req2, findings2 = monitor.check_ioc("1.2.3.4", "ip")
    assert req2["method"] == "POST"
    assert len(findings2) == 2
