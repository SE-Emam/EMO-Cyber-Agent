"""Dark-web / breach-leak intelligence — DEFENSIVE KNOWLEDGE ONLY.

This module holds *knowledge about* public breach-intelligence APIs and
*parsers for already-obtained* response payloads. It performs triage over
digests, never over raw identifiers.

Non-negotiable boundaries:

- Nothing here executes, exploits, scans live targets, or crawls.
- No network calls anywhere. :func:`hibp_breach_request` and
  :func:`threatfox_ioc_request` build plain data dicts describing a
  request (endpoint, method, params) for documented public APIs; they
  never send anything.
- Fetching is only possible through caller-injected callables, and
  :class:`DarkLeakMonitor` refuses to fetch when no fetcher was
  supplied.
- Raw identifiers (accounts, IOC values, secrets) are hashed with
  SHA-256 immediately on parse and are never stored on findings.

Shape reuses frozen-pydantic conventions (``frozen=True``,
``extra="forbid"``, ``to_dict`` / ``from_dict`` /
``to_canonical_json``, kebab-case ids).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "SPEC_VERSION",
    "HIBP_API_BASE",
    "THREATFOX_API_URL",
    "THREATFOX_IOC_TYPES",
    "LeakFinding",
    "LeakTriageVerdict",
    "DarkLeakMonitor",
    "hibp_breach_request",
    "threatfox_ioc_request",
    "parse_hibp_response",
    "parse_threatfox_response",
    "triage",
    "triage_leak",
    "sha256_hex",
]

SPEC_VERSION = "1.0.0"

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

THREATFOX_IOC_TYPES: tuple[str, ...] = ("ip", "domain", "url", "hash", "md5", "sha1", "sha256")

LeakTriageVerdict = Literal["RELEVANT", "UNRELATED", "QUARANTINE"]

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_hex(raw: str) -> str:
    """Hex SHA-256 of a raw identifier. The raw value is never retained."""
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def _non_blank(label: str, value: str, max_len: int = 500) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{label} must be non-empty")
    if len(text) > max_len:
        raise ValueError(f"{label} must be at most {max_len} chars")
    return text


class LeakFinding(BaseModel):
    """One parsed leak-intelligence record. Digest only — never raw.

    ``identifier_digest`` is the hex SHA-256 of the queried account or
    IOC value. ``name`` is the breach / threat label, ``date`` the
    source-reported date string (may be empty when unknown).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(...)
    source: Literal["hibp", "threatfox"] = Field(...)
    identifier_digest: str = Field(...)
    name: str = Field(min_length=1, max_length=300)
    date: str = Field(default="", max_length=64)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    @field_validator("finding_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("finding_id must be kebab-case")
        return v

    @field_validator("identifier_digest")
    @classmethod
    def _digest(cls, v: str) -> str:
        if not _DIGEST_RE.match(v):
            raise ValueError("identifier_digest must be hex sha256")
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def hibp_breach_request(account_or_domain: str, truncate_response: bool = True) -> dict[str, Any]:
    """Build (never send) a HaveIBeenPwned breached-account request dict.

    References the documented public endpoint
    ``haveibeenpwned.com/api/v3``. The caller performs transport.
    """
    account = _non_blank("account_or_domain", account_or_domain, max_len=320)
    return {
        "endpoint": f"{HIBP_API_BASE}/breachedaccount/{account}",
        "method": "GET",
        "params": {"truncateResponse": bool(truncate_response)},
    }


def threatfox_ioc_request(ioc: str, ioc_type: str = "hash") -> dict[str, Any]:
    """Build (never send) a ThreatFox ``search_ioc`` request dict.

    References the documented public endpoint
    ``threatfox-api.abuse.ch``. The caller performs transport.
    """
    value = _non_blank("ioc", ioc, max_len=2048)
    kind = (ioc_type or "").strip().lower()
    if kind not in THREATFOX_IOC_TYPES:
        raise ValueError(f"unknown threatfox ioc type: {ioc_type!r}")
    return {
        "endpoint": THREATFOX_API_URL,
        "method": "POST",
        "params": {"query": "search_ioc", "search_term": value, "ioc_type": kind},
    }


def _hibp_confidence(entry: dict[str, Any]) -> float:
    if "confidence" in entry:
        try:
            return max(0.0, min(1.0, float(entry["confidence"])))
        except (TypeError, ValueError):
            pass
    verified = entry.get("IsVerified")
    if verified is True:
        return 0.9
    if verified is False:
        return 0.6
    return 0.7


def parse_hibp_response(payload: Any) -> list[LeakFinding]:
    """Parse an already-obtained HIBP payload into digest-only findings.

    Accepted shapes (all plain data, no transport):

    - ``{"account": "<raw>", "breaches": [{...}, ...]}`` (preferred:
      the queried account is hashed into ``identifier_digest``);
    - a bare ``[{...}, ...]`` breach list, in which case each finding
      digests ``"unknown-identifier:<Name>"`` as the documented
      fallback when the queried account is not supplied.

    Each breach entry honours ``Name`` (label), ``BreachDate`` (date),
    and ``IsVerified`` (confidence hint). Raises :class:`ValueError`
    on structurally unusable payloads.
    """
    if isinstance(payload, dict):
        account = payload.get("account", payload.get("identifier", ""))
        breaches = payload.get("breaches", payload.get("data", []))
    elif isinstance(payload, list):
        account, breaches = "", payload
    else:
        raise ValueError("hibp payload must be a dict or list")
    if not isinstance(breaches, list):
        raise ValueError("hibp breaches must be a list")
    account = (account or "").strip()
    findings: list[LeakFinding] = []
    for index, entry in enumerate(breaches):
        if not isinstance(entry, dict):
            raise ValueError(f"hibp breach entry {index} must be a dict")
        name = str(entry.get("Name", entry.get("name", ""))).strip()
        if not name:
            raise ValueError(f"hibp breach entry {index} has no Name")
        date = str(entry.get("BreachDate", entry.get("AddedDate", entry.get("date", "")))).strip()
        seed = account if account else f"unknown-identifier:{name}"
        digest = sha256_hex(seed)
        findings.append(
            LeakFinding(
                finding_id=f"hibp-{digest[:12]}-{index:04d}",
                source="hibp",
                identifier_digest=digest,
                name=name[:300],
                date=date[:64],
                confidence=_hibp_confidence(entry),
            )
        )
    return findings


def _threatfox_confidence(entry: dict[str, Any]) -> float:
    level = entry.get("confidence_level", entry.get("confidence", 0.5))
    if isinstance(level, (int, float)):
        try:
            return max(0.0, min(1.0, float(level) / 100.0 if float(level) > 1.0 else float(level)))
        except (TypeError, ValueError):
            return 0.5
    mapping = {"high": 0.9, "medium": 0.6, "low": 0.3}
    return mapping.get(str(level).strip().lower(), 0.5)


def parse_threatfox_response(payload: Any) -> list[LeakFinding]:
    """Parse an already-obtained ThreatFox payload into digest-only findings.

    Accepted shapes: ``{"data": [{...}, ...]}`` (as returned by the
    documented ``search_ioc`` query) or a bare ``[{...}, ...]`` list.
    Each item honours ``ioc`` (hashed immediately, never stored),
    ``threat_type`` / ``malware_printable`` (label), and
    ``first_seen`` (date). Raises :class:`ValueError` on structurally
    unusable payloads.
    """
    if isinstance(payload, dict):
        items = payload.get("data", payload.get("iocs", []))
    elif isinstance(payload, list):
        items = payload
    else:
        raise ValueError("threatfox payload must be a dict or list")
    if not isinstance(items, list):
        raise ValueError("threatfox data must be a list")
    findings: list[LeakFinding] = []
    for index, entry in enumerate(items):
        if not isinstance(entry, dict):
            raise ValueError(f"threatfox entry {index} must be a dict")
        ioc = str(entry.get("ioc", entry.get("search_term", ""))).strip()
        if not ioc:
            raise ValueError(f"threatfox entry {index} has no ioc")
        label = str(
            entry.get("threat_type", entry.get("malware_printable", entry.get("threat", "")))
        ).strip() or "threatfox-ioc"
        date = str(entry.get("first_seen", entry.get("date", ""))).strip()
        digest = sha256_hex(ioc)
        findings.append(
            LeakFinding(
                finding_id=f"threatfox-{digest[:12]}-{index:04d}",
                source="threatfox",
                identifier_digest=digest,
                name=label[:300],
                date=date[:64],
                confidence=_threatfox_confidence(entry),
            )
        )
    return findings


def _coerce_finding(leak: Any) -> LeakFinding | None:
    if isinstance(leak, LeakFinding):
        return leak
    if isinstance(leak, dict):
        try:
            return LeakFinding.model_validate(leak)
        except Exception:
            return None
    return None


def triage(leak: Any, scope: Any) -> LeakTriageVerdict:
    """Triage one leak finding against a scope of identifier digests.

    ``scope`` is an iterable of hex SHA-256 digests (never raw
    identifiers). Returns ``RELEVANT`` when the finding's digest is in
    scope, ``UNRELATED`` when it parses but is out of scope, and
    ``QUARANTINE`` when the finding itself is unparseable.
    """
    finding = _coerce_finding(leak)
    if finding is None:
        return "QUARANTINE"
    try:
        allowed = {(d or "").strip().lower() for d in (scope or ())}
    except TypeError:
        return "QUARANTINE"
    allowed = {d for d in allowed if _DIGEST_RE.match(d)}
    if finding.identifier_digest.lower() in allowed:
        return "RELEVANT"
    return "UNRELATED"


triage_leak = triage


class DarkLeakMonitor:
    """Leak-intelligence facade over injected fetchers. Refuses by default.

    ``hibp_fetcher`` / ``threatfox_fetcher`` are optional callables
    taking a request dict (as built by :func:`hibp_breach_request` /
    :func:`threatfox_ioc_request`) and returning an already-obtained
    payload for the pure parsers. With no fetcher configured, every
    fetch method raises :class:`RuntimeError` instead of touching the
    network (there is no network code path at all).
    """

    def __init__(
        self,
        hibp_fetcher: Callable[[dict[str, Any]], Any] | None = None,
        threatfox_fetcher: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self._hibp_fetcher = hibp_fetcher
        self._threatfox_fetcher = threatfox_fetcher

    @property
    def has_hibp_fetcher(self) -> bool:
        return self._hibp_fetcher is not None

    @property
    def has_threatfox_fetcher(self) -> bool:
        return self._threatfox_fetcher is not None

    def build_hibp_request(
        self, account_or_domain: str, truncate_response: bool = True
    ) -> dict[str, Any]:
        return hibp_breach_request(account_or_domain, truncate_response)

    def build_threatfox_request(self, ioc: str, ioc_type: str = "hash") -> dict[str, Any]:
        return threatfox_ioc_request(ioc, ioc_type)

    def fetch_hibp(self, request: dict[str, Any]) -> Any:
        if self._hibp_fetcher is None:
            raise RuntimeError("hibp fetch refused: no fetcher configured")
        return self._hibp_fetcher(request)

    def fetch_threatfox(self, request: dict[str, Any]) -> Any:
        if self._threatfox_fetcher is None:
            raise RuntimeError("threatfox fetch refused: no fetcher configured")
        return self._threatfox_fetcher(request)

    def check_account(self, account_or_domain: str) -> tuple[dict[str, Any], list[LeakFinding]]:
        """Build the HIBP request, fetch via the injected fetcher, parse."""
        request = self.build_hibp_request(account_or_domain)
        payload = self.fetch_hibp(request)
        return request, parse_hibp_response(payload)

    def check_ioc(
        self, ioc: str, ioc_type: str = "hash"
    ) -> tuple[dict[str, Any], list[LeakFinding]]:
        """Build the ThreatFox request, fetch via the injected fetcher, parse."""
        request = self.build_threatfox_request(ioc, ioc_type)
        payload = self.fetch_threatfox(request)
        return request, parse_threatfox_response(payload)

    def triage(self, leak: Any, scope: Any) -> LeakTriageVerdict:
        return triage(leak, scope)
