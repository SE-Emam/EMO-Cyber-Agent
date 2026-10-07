"""Threat-feed IoC fusion and triage — DEFENSIVE KNOWLEDGE ONLY.

Pure, deterministic matching of caller-supplied indicators of
compromise against caller-supplied finding records, plus deterministic
prioritization over caller-supplied KEV / EPSS data.

Non-negotiable boundaries:

- Nothing here executes, exploits, scans live targets, or crawls.
- No network calls anywhere: KEV sets and EPSS maps are supplied by
  the caller; nothing is fetched.
- No randomness, no clock: identical inputs always yield identical
  outputs (finding iteration is sorted by ref).

Shape reuses frozen-pydantic conventions (``frozen=True``,
``extra="forbid"``, ``to_dict`` / ``from_dict`` /
``to_canonical_json``, kebab-case ids).
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "SPEC_VERSION",
    "IOC_KINDS",
    "IoC",
    "FeedFinding",
    "TriageVerdict",
    "ThreatFeedTriage",
    "ioc_ref",
    "normalize_value",
    "match",
    "match_ioc",
    "prioritize",
]

SPEC_VERSION = "1.0.0"

IOC_KINDS: tuple[str, ...] = ("ip", "domain", "url", "hash")

IoCKind = Literal["ip", "domain", "url", "hash"]
Verdict = Literal["RELEVANT", "UNRELATED"]

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9\-]+(\.[a-z0-9\-]+)+$")


def normalize_value(kind: str, value: str) -> str:
    """Deterministic normal form for an IoC/finding value."""
    text = (value or "").strip()
    if (kind or "").strip().lower() in ("domain", "hash"):
        text = text.lower()
    if (kind or "").strip().lower() == "url":
        text = text.lower()
    return text


def ioc_ref(ioc: "IoC") -> str:
    """Stable human-readable reference ``<kind>:<normalized-value>``."""
    return f"{ioc.kind}:{normalize_value(ioc.kind, ioc.value)}"


class IoC(BaseModel):
    """One caller-supplied indicator of compromise. Data only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: IoCKind = Field(...)
    value: str = Field(min_length=1, max_length=2048)
    source: str = Field(min_length=1, max_length=120)
    first_seen: str = Field(default="", max_length=64)

    @field_validator("value")
    @classmethod
    def _value(cls, v: str, info: Any) -> str:
        text = (v or "").strip()
        if not text:
            raise ValueError("value must be non-empty")
        kind = (info.data.get("kind") or "").strip().lower() if info.data else ""
        if kind == "ip":
            try:
                ipaddress.ip_address(text)
            except ValueError:
                raise ValueError(f"invalid ip value: {text!r}") from None
        if kind == "domain" and not _DOMAIN_RE.match(text.lower()):
            raise ValueError(f"invalid domain value: {text!r}")
        return text

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class FeedFinding(BaseModel):
    """One caller-supplied finding record eligible for IoC matching."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ref: str = Field(...)
    value: str = Field(min_length=1, max_length=2048)

    @field_validator("ref")
    @classmethod
    def _ref(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("ref must be kebab-case")
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class TriageVerdict(BaseModel):
    """Deterministic outcome of matching one IoC against findings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ioc_ref: str = Field(min_length=1, max_length=2100)
    matched_finding_refs: tuple[str, ...] = Field(default_factory=tuple)
    verdict: Verdict = Field(...)
    reasons: tuple[str, ...] = Field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _finding_pairs(findings: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for entry in findings or ():
        if isinstance(entry, FeedFinding):
            pairs.append((entry.ref, entry.value))
        elif isinstance(entry, dict) and entry.get("ref") and entry.get("value") is not None:
            ref = str(entry["ref"])
            if _ID_RE.match(ref):
                pairs.append((ref, str(entry["value"])))
    pairs.sort(key=lambda pair: pair[0])
    return pairs


def _looks_like_bare_domain(text: str) -> bool:
    return bool(_DOMAIN_RE.match((text or "").strip().lower()))


def match(ioc: IoC | dict[str, Any], findings: Any) -> TriageVerdict:
    """Match one IoC against finding records, deterministically.

    Rules (evaluated in this order per finding, findings iterated in
    sorted-ref order):

    - exact value match (kind-aware normalization);
    - IPv4 CIDR containment (finding value is a CIDR, IoC is an IPv4
      address inside it; invalid CIDRs are ignored, never fatal);
    - domain suffix match (either side is a dot-suffix of the other).

    Returns a :class:`TriageVerdict` with verdict ``RELEVANT`` when at
    least one rule fires, else ``UNRELATED``. Reasons are sorted, so
    repeated calls are byte-identical.
    """
    if isinstance(ioc, dict):
        ioc = IoC.model_validate(ioc)
    if not isinstance(ioc, IoC):
        raise ValueError("ioc must be an IoC or IoC dict")
    want = normalize_value(ioc.kind, ioc.value)
    matched: list[str] = []
    reasons: list[str] = []
    for ref, raw in _finding_pairs(findings):
        got = normalize_value(ioc.kind, raw)
        if got == want:
            matched.append(ref)
            reasons.append(f"exact-value-match:{ref}")
            continue
        if ioc.kind == "ip" and "/" in got:
            try:
                network = ipaddress.ip_network(got, strict=False)
                addr = ipaddress.ip_address(want)
            except ValueError:
                network, addr = None, None
            if (
                network is not None
                and addr is not None
                and network.version == 4
                and addr.version == 4
                and addr in network
            ):
                matched.append(ref)
                reasons.append(f"cidr-containment:{ref}")
                continue
        if ioc.kind == "domain" and _looks_like_bare_domain(want) and _looks_like_bare_domain(got):
            if want.endswith("." + got) or got.endswith("." + want):
                matched.append(ref)
                reasons.append(f"domain-suffix-match:{ref}")
    matched = sorted(set(matched))
    reasons = sorted(set(reasons))
    return TriageVerdict(
        ioc_ref=ioc_ref(ioc),
        matched_finding_refs=tuple(matched),
        verdict="RELEVANT" if matched else "UNRELATED",
        reasons=tuple(reasons),
    )


match_ioc = match


def _item_ref(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("ref", item.get("id", item.get("cve_id", ""))))
    for attr in ("ref", "id", "cve_id"):
        if hasattr(item, attr):
            return str(getattr(item, attr))
    return ""


def _item_severity(item: Any) -> float:
    raw: Any = None
    if isinstance(item, dict):
        raw = item.get("severity", item.get("score", 0.0))
    elif hasattr(item, "severity"):
        raw = getattr(item, "severity")
    try:
        return max(0.0, float(raw))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _item_cve(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("cve_id", item.get("cve", ""))).strip().upper()
    for attr in ("cve_id", "cve"):
        if hasattr(item, attr):
            return str(getattr(item, attr)).strip().upper()
    return ""


def prioritize(items: Any, kev_set: Any, epss_map: Any) -> list[Any]:
    """Sort triage items by (KEV-match, EPSS desc, severity desc, ref).

    ``kev_set`` is a caller-supplied set of KEV identifiers (CVE ids or
    refs); ``epss_map`` maps ref-or-CVE to an EPSS score. Nothing is
    fetched. Items may be dicts or objects exposing ``ref``/``severity``
    (and optionally ``cve_id``). The input sequence is never mutated; a
    new sorted list is returned.
    """
    kev = {str(k).strip().upper() for k in (kev_set or ())}
    epss_lookup = dict(epss_map or {})

    def _epss(ref: str, cve: str) -> float:
        for key in (ref, ref.upper(), cve, cve.upper()):
            if key and key in epss_lookup:
                try:
                    return max(0.0, min(1.0, float(epss_lookup[key])))
                except (TypeError, ValueError):
                    return 0.0
        return 0.0

    decorated: list[tuple[tuple[int, float, float, str], int, Any]] = []
    for index, item in enumerate(items or ()):
        ref = _item_ref(item)
        cve = _item_cve(item)
        is_kev = bool((ref and ref.upper() in kev) or (cve and cve in kev))
        score = _epss(ref, cve)
        severity = _item_severity(item)
        key = (0 if is_kev else 1, -score, -severity, ref)
        decorated.append((key, index, item))
    decorated.sort(key=lambda entry: (entry[0], entry[1]))
    return [item for _, _, item in decorated]


class ThreatFeedTriage:
    """Facade over the pure :func:`match` / :func:`prioritize` functions."""

    def match(self, ioc: IoC | dict[str, Any], findings: Any) -> TriageVerdict:
        return match(ioc, findings)

    def prioritize(self, items: Any, kev_set: Any, epss_map: Any) -> list[Any]:
        return prioritize(items, kev_set, epss_map)

    def ioc_ref(self, ioc: IoC | dict[str, Any]) -> str:
        if isinstance(ioc, dict):
            ioc = IoC.model_validate(ioc)
        return ioc_ref(ioc)
