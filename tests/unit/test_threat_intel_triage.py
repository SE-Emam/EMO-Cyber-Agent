"""Threat-feed IoC triage tests (offline, deterministic).

Exact, CIDR, and domain-suffix match classes, CIDR edges,
prioritization order, determinism, and a no-network AST guard.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from emo_cyber_agent.threat_intel.feed_triage import (
    FeedFinding,
    IoC,
    ThreatFeedTriage,
    ioc_ref,
    match,
    prioritize,
)

PACKAGE_DIR = Path(__file__).resolve().parents[2] / "src" / "emo_cyber_agent" / "threat_intel"
FORBIDDEN_IMPORTS = frozenset(
    {"socket", "urllib", "http", "requests", "httpx", "aiohttp", "urllib3",
     "ftplib", "smtplib", "telnetlib", "websockets", "subprocess"}
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


def test_exact_ip_match() -> None:
    ioc = IoC(kind="ip", value="1.2.3.4", source="feed-a", first_seen="2024-01-01")
    verdict = match(ioc, [{"ref": "finding-one", "value": "1.2.3.4"}])
    assert verdict.verdict == "RELEVANT"
    assert verdict.matched_finding_refs == ("finding-one",)
    assert verdict.reasons == ("exact-value-match:finding-one",)
    assert verdict.ioc_ref == "ip:1.2.3.4"


def test_exact_hash_and_url_match() -> None:
    digest = "44d88612fea8a8f36de82e1278abb02f"
    ioc = IoC(kind="hash", value=digest.upper(), source="feed-a", first_seen="2024-01-01")
    verdict = match(ioc, [FeedFinding(ref="finding-hash", value=digest)])
    assert verdict.verdict == "RELEVANT"
    url = IoC(kind="url", value="http://evil.example.com/x", source="feed-a",
              first_seen="2024-01-01")
    verdict = match(url, [{"ref": "finding-url", "value": "http://evil.example.com/x"}])
    assert verdict.verdict == "RELEVANT"


def test_no_match_is_unrelated() -> None:
    ioc = IoC(kind="ip", value="9.9.9.9", source="feed-a", first_seen="2024-01-01")
    verdict = match(ioc, [{"ref": "finding-one", "value": "1.2.3.4"}])
    assert verdict.verdict == "UNRELATED"
    assert verdict.matched_finding_refs == ()
    assert verdict.reasons == ()


def test_cidr_containment_match() -> None:
    ioc = IoC(kind="ip", value="10.0.0.5", source="feed-a", first_seen="2024-01-01")
    verdict = match(ioc, [{"ref": "finding-net", "value": "10.0.0.0/24"}])
    assert verdict.verdict == "RELEVANT"
    assert verdict.reasons == ("cidr-containment:finding-net",)


def test_cidr_edges() -> None:
    inside = IoC(kind="ip", value="10.0.0.1", source="f", first_seen="2024-01-01")
    assert match(inside, [{"ref": "net-a", "value": "10.0.0.1/32"}]).verdict == "RELEVANT"
    outside = IoC(kind="ip", value="10.0.1.1", source="f", first_seen="2024-01-01")
    assert match(outside, [{"ref": "net-a", "value": "10.0.0.0/24"}]).verdict == "UNRELATED"
    # Invalid CIDR findings are ignored, never fatal.
    assert match(outside, [{"ref": "net-bad", "value": "999.0.0.0/99"}]).verdict == "UNRELATED"
    # IPv6 addresses are not matched by IPv4 CIDR containment.
    v6 = IoC(kind="ip", value="::1", source="f", first_seen="2024-01-01")
    assert match(v6, [{"ref": "net-a", "value": "0.0.0.0/0"}]).verdict == "UNRELATED"


def test_domain_suffix_match() -> None:
    ioc = IoC(kind="domain", value="sub.example.com", source="f", first_seen="2024-01-01")
    verdict = match(ioc, [{"ref": "finding-parent", "value": "example.com"}])
    assert verdict.verdict == "RELEVANT"
    assert verdict.reasons == ("domain-suffix-match:finding-parent",)


def test_domain_suffix_case_insensitive_and_reverse() -> None:
    ioc = IoC(kind="domain", value="EXAMPLE.com", source="f", first_seen="2024-01-01")
    verdict = match(ioc, [{"ref": "finding-child", "value": "Sub.Example.COM"}])
    assert verdict.verdict == "RELEVANT"
    other = IoC(kind="domain", value="unrelated.example.org", source="f", first_seen="2024-01-01")
    assert match(other, [{"ref": "finding-parent", "value": "example.com"}]).verdict == "UNRELATED"
    # Lookalikes without a dot boundary do not match.
    trick = IoC(kind="domain", value="notexample.com", source="f", first_seen="2024-01-01")
    assert match(trick, [{"ref": "finding-parent", "value": "example.com"}]).verdict == "UNRELATED"


def test_match_deterministic_under_reordering() -> None:
    ioc = IoC(kind="ip", value="10.0.0.5", source="f", first_seen="2024-01-01")
    findings_a = [
        {"ref": "finding-b", "value": "10.0.0.0/24"},
        {"ref": "finding-a", "value": "10.0.0.5"},
    ]
    findings_b = list(reversed(findings_a))
    first = match(ioc, findings_a)
    second = match(ioc, findings_b)
    assert first.to_canonical_json() == second.to_canonical_json()
    assert first.matched_finding_refs == ("finding-a", "finding-b")
    assert first.reasons == ("cidr-containment:finding-b", "exact-value-match:finding-a")


def test_match_rejects_bad_ioc() -> None:
    with pytest.raises(Exception):
        match({"kind": "ip", "value": "not-an-ip", "source": "f"}, [])
    with pytest.raises(Exception):
        IoC(kind="domain", value="not a domain!!", source="f")
    with pytest.raises(Exception):
        IoC(kind="carrier-pigeon", value="x", source="f")  # type: ignore[arg-type]


def test_ioc_ref_stable() -> None:
    ioc = IoC(kind="domain", value="Sub.Example.COM", source="f", first_seen="2024-01-01")
    assert ioc_ref(ioc) == "domain:sub.example.com"


def test_prioritize_kev_then_epss_then_severity() -> None:
    items = [
        {"ref": "item-low-epss", "severity": 9.8},
        {"ref": "item-high-epss", "severity": 4.0},
        {"ref": "item-kev", "severity": 1.0, "cve_id": "CVE-2021-44228"},
        {"ref": "item-mid", "severity": 7.0},
    ]
    kev = {"CVE-2021-44228"}
    epss = {"item-high-epss": 0.9, "item-mid": 0.5, "item-low-epss": 0.1}
    ordered = prioritize(items, kev, epss)
    assert [i["ref"] for i in ordered] == ["item-kev", "item-high-epss", "item-mid",
                                            "item-low-epss"]


def test_prioritize_tiebreak_and_no_mutation() -> None:
    items = [
        {"ref": "item-b", "severity": 5.0},
        {"ref": "item-a", "severity": 5.0},
    ]
    snapshot = [dict(i) for i in items]
    ordered = prioritize(items, set(), {})
    assert [i["ref"] for i in ordered] == ["item-a", "item-b"]
    assert items == snapshot
    assert ordered is not items


def test_prioritize_uses_caller_data_only() -> None:
    items = [{"ref": "item-x", "severity": 2.0}]
    assert prioritize(items, set(), {})[0]["ref"] == "item-x"
    assert prioritize(items, {"item-x"}, {})[0]["ref"] == "item-x"
    # Unknown EPSS keys never crash.
    assert prioritize(items, set(), {"nope": "junk"})[0]["ref"] == "item-x"


def test_service_facade() -> None:
    service = ThreatFeedTriage()
    ioc = IoC(kind="ip", value="1.2.3.4", source="f", first_seen="2024-01-01")
    verdict = service.match(ioc, [{"ref": "finding-one", "value": "1.2.3.4"}])
    assert verdict.verdict == "RELEVANT"
    assert service.ioc_ref(ioc) == "ip:1.2.3.4"
    ordered = service.prioritize([{"ref": "a", "severity": 1.0}], set(), {})
    assert [i["ref"] for i in ordered] == ["a"]
