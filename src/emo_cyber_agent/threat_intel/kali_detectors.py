"""Kali tool detector pack — DEFENSIVE KNOWLEDGE ONLY.

A static, curated record for 20 well-known offensive tools describing,
for defenders: which misconfigurations each tool abuses, which EMO-side
evidence proves exposure, and which fix direction removes it.
:func:`detect_exposure` reasons over caller-supplied facts (open ports,
banners, auth posture, rate limits, secrets, headers) with pure logic.

Non-negotiable boundaries:

- Nothing here executes, exploits, scans live targets, or crawls.
- No probing: this module never opens sockets or spawns processes; it
  only interprets facts the caller already collected.
- No network calls, no randomness, no clock.

Shape reuses frozen-pydantic conventions (``frozen=True``,
``extra="forbid"``, ``to_dict`` / ``from_dict`` /
``to_canonical_json``, kebab-case ids).
"""

from __future__ import annotations

import json
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "TABLE_VERSION",
    "TOOL_CATEGORIES",
    "TOOL_NAMES",
    "KaliTool",
    "ExposureReport",
    "CoverageReport",
    "KaliToolDetectorPack",
    "all_tool_names",
    "get_tool",
    "detect_exposure",
    "coverage",
]

TABLE_VERSION = "1.0.0"

TOOL_CATEGORIES: tuple[str, ...] = (
    "recon",
    "exploitation",
    "web",
    "password",
    "sniffing",
    "wireless",
    "forensics",
    "osint",
)

ToolCategory = Literal[
    "recon", "exploitation", "web", "password", "sniffing", "wireless", "forensics", "osint"
]

TOOL_NAMES: tuple[str, ...] = (
    "nmap",
    "metasploit-framework",
    "burpsuite",
    "sqlmap",
    "hydra",
    "john",
    "wireshark",
    "aircrack-ng",
    "nikto",
    "gobuster",
    "hashcat",
    "responder",
    "mimikatz",
    "empire",
    "bloodhound",
    "netcat",
    "socat",
    "theharvester",
    "maltego",
    "zaproxy",
)

_SECURITY_HEADERS = ("content-security-policy", "x-frame-options", "strict-transport-security")


class KaliTool(BaseModel):
    """One curated defensive record for a well-known offensive tool."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    category: ToolCategory = Field(...)
    abuses: tuple[str, ...] = Field(min_length=1)
    detects: tuple[str, ...] = Field(min_length=1)
    guidance: str = Field(min_length=1, max_length=2000)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        text = (v or "").strip().lower()
        if text not in TOOL_NAMES:
            raise ValueError(f"unknown kali tool: {v!r}")
        return text

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class ExposureReport(BaseModel):
    """Outcome of reasoning over caller-supplied facts. No probing involved."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str = Field(min_length=1, max_length=80)
    exposed: bool = Field(...)
    reasons: tuple[str, ...] = Field(min_length=1)
    guidance: str = Field(min_length=1, max_length=2000)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class CoverageReport(BaseModel):
    """Which tools have EMO-side detection; gaps are listed honestly."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tools: tuple[str, ...] = Field(default_factory=tuple)
    capabilities: tuple[str, ...] = Field(default_factory=tuple)
    covered: tuple[str, ...] = Field(default_factory=tuple)
    gaps: tuple[str, ...] = Field(default_factory=tuple)
    coverage_ratio: float = Field(ge=0.0, le=1.0)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _tool(
    name: str,
    category: ToolCategory,
    abuses: tuple[str, ...],
    detects: tuple[str, ...],
    guidance: str,
) -> KaliTool:
    return KaliTool(
        name=name, category=category, abuses=abuses, detects=detects, guidance=guidance
    )


TOOLS: tuple[KaliTool, ...] = (
    _tool(
        "nmap", "recon",
        ("exposed network services", "verbose service banners", "unfiltered ports"),
        ("open-ports", "service-banners", "unexpected-services"),
        "Minimize exposed ports, filter at the boundary, and strip version banners.",
    ),
    _tool(
        "metasploit-framework", "exploitation",
        ("unpatched public services", "missing authentication on services",
         "deserialization endpoints"),
        ("unpatched-services", "missing-auth", "open-ports"),
        "Patch public components, require authentication on every service, and segment networks.",
    ),
    _tool(
        "burpsuite", "web",
        ("missing security headers", "verbose error pages", "unthrottled login forms"),
        ("missing-security-headers", "verbose-errors", "missing-rate-limit"),
        "Emit security headers, suppress verbose errors, and throttle authentication endpoints.",
    ),
    _tool(
        "sqlmap", "web",
        ("unsanitized query inputs", "verbose database errors", "stacked-query support"),
        ("verbose-errors", "unsanitized-inputs", "missing-auth"),
        "Use parameterized queries, suppress backend errors, and least-privilege DB accounts.",
    ),
    _tool(
        "hydra", "password",
        ("password logons without rate limiting", "missing lockout", "no MFA"),
        ("password-auth", "missing-rate-limit", "missing-mfa"),
        "Enforce rate limiting with lockout or delays and require MFA on remote logons.",
    ),
    _tool(
        "john", "password",
        ("exposed password hashes", "weak hashing schemes", "password reuse"),
        ("exposed-hashes", "weak-hashing", "exposed-secrets"),
        "Stop hash disclosure, migrate to memory-hard hashing, and enforce MFA.",
    ),
    _tool(
        "wireshark", "sniffing",
        ("cleartext protocols", "unencrypted credentials on the wire", "SPAN-port exposure"),
        ("cleartext-traffic", "exposed-secrets", "missing-tls"),
        "Enforce TLS everywhere, disable cleartext fallbacks, and restrict capture points.",
    ),
    _tool(
        "aircrack-ng", "wireless",
        ("weak WPA passphrases", "WEP or open networks", "WPS left enabled"),
        ("weak-wireless", "legacy-encryption", "open-networks"),
        "Use WPA3 or strong WPA2 passphrases, disable WPS, and retire WEP/open networks.",
    ),
    _tool(
        "nikto", "web",
        ("outdated server software", "dangerous default files", "verbose banners"),
        ("outdated-software", "default-files", "service-banners"),
        "Patch servers, remove default content, and strip version banners.",
    ),
    _tool(
        "gobuster", "recon",
        ("predictable hidden paths", "backup files under web roots", "verbose listings"),
        ("predictable-paths", "service-banners", "directory-listing"),
        "Remove backup and temp files from web roots and disable directory listings.",
    ),
    _tool(
        "hashcat", "password",
        ("exposed password hashes", "fast unsalted hashes", "credential dumps"),
        ("exposed-hashes", "weak-hashing", "exposed-secrets"),
        "Prevent hash disclosure, use memory-hard hashes with unique salts, and require MFA.",
    ),
    _tool(
        "responder", "exploitation",
        ("LLMNR/NBT-NS responder left enabled", "unsigned SMB", "cleartext auth fallbacks"),
        ("name-poisoning-surface", "unsigned-smb", "missing-auth"),
        "Disable LLMNR/NBT-NS, enforce SMB signing, and block legacy auth fallbacks.",
    ),
    _tool(
        "mimikatz", "exploitation",
        ("credentials in LSASS-equivalent memory", "cached hashes", "cleartext secrets on hosts"),
        ("credential-caching", "exposed-hashes", "exposed-secrets"),
        "Use credential-guard style isolation, deny debug privileges, and shorten lifetimes.",
    ),
    _tool(
        "empire", "exploitation",
        ("macro-enabled documents", "unconstrained scripting runtimes", "weak endpoint controls"),
        ("macro-execution", "scripting-abuse", "missing-auth"),
        "Block macros from the internet, constrain scripting, and enforce application control.",
    ),
    _tool(
        "bloodhound", "recon",
        ("over-privileged service accounts", "flat AD-class trust", "stale privileged groups"),
        ("privilege-paths", "stale-groups", "open-ports"),
        "Tier privileges, clean stale group membership, and audit attack paths regularly.",
    ),
    _tool(
        "netcat", "exploitation",
        ("unrestricted outbound egress", "unexpected listeners", "missing egress filtering"),
        ("unexpected-listeners", "open-ports", "missing-auth"),
        "Default-deny egress, alert on unexpected listeners, and remove shell tools from servers.",
    ),
    _tool(
        "socat", "exploitation",
        ("unrestricted relays and forwarders", "unexpected TLS endpoints",
         "missing egress filtering"),
        ("unexpected-listeners", "unexpected-relays", "open-ports"),
        "Default-deny egress and forwarding, and alert on unexpected relay processes.",
    ),
    _tool(
        "theharvester", "osint",
        ("breached third-party credentials", "public DNS and cert transparency data",
         "oversharing staff"),
        ("leaked-credentials", "public-records", "exposed-secrets"),
        "Monitor breach-intelligence digests, shrink public records, and rotate leaked secrets.",
    ),
    _tool(
        "maltego", "osint",
        ("linked public records", "overshared infrastructure data", "breached credentials"),
        ("public-records", "leaked-credentials", "exposed-secrets"),
        "Minimize public footprint, monitor breach data, and segment infrastructure identities.",
    ),
    _tool(
        "zaproxy", "web",
        ("missing security headers", "verbose error pages", "unthrottled forms"),
        ("missing-security-headers", "verbose-errors", "missing-rate-limit"),
        "Emit security headers, suppress verbose errors, and throttle authentication endpoints.",
    ),
)

_BY_NAME: dict[str, KaliTool] = {t.name: t for t in TOOLS}


def all_tool_names() -> tuple[str, ...]:
    """Sorted names of all 20 catalogued tools."""
    return tuple(sorted(_BY_NAME))


def get_tool(tool_name: str) -> KaliTool:
    """Return the record for a known tool; raise ValueError otherwise."""
    key = (tool_name or "").strip().lower()
    try:
        return _BY_NAME[key]
    except KeyError:
        raise ValueError(f"unknown kali tool: {tool_name!r}") from None


def _as_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{k} {v}" for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(v) for v in value)
    return str(value or "")


def _missing_security_headers(headers: Any) -> list[str]:
    if not isinstance(headers, dict):
        return []
    present = {str(k).lower() for k in headers}
    return [h for h in _SECURITY_HEADERS if h not in present]


def _evaluate(tool: KaliTool, facts: dict[str, Any]) -> tuple[bool, list[str]]:
    """Pure-logic exposure rules over caller-supplied facts. No probing."""
    open_ports = facts.get("open_ports") or []
    banners = facts.get("banners")
    auth = facts.get("auth")
    rate_limit = facts.get("rate_limit")
    secrets = facts.get("secrets")
    headers = facts.get("headers")
    banner_text = _as_text(banners).lower()
    secrets_present = bool(secrets) if not isinstance(secrets, bool) else secrets
    ports_open = isinstance(open_ports, (list, tuple)) and len(open_ports) > 0
    auth_enforced = auth is True or (
        isinstance(auth, str) and auth.strip().lower() in ("true", "enforced", "yes", "mfa")
    )
    rate_enforced = rate_limit is True or (
        isinstance(rate_limit, str) and rate_limit.strip().lower() in ("true", "enforced", "yes")
    )
    reasons: list[str] = []

    name = tool.name
    if name == "hydra":
        if auth_enforced and not rate_enforced:
            reasons.append("password-auth-without-rate-limit")
        elif auth_enforced and rate_enforced:
            return False, ["rate-limit-enforced"]
        else:
            return False, ["no-password-auth-surface"]
    elif name in ("john", "hashcat"):
        if secrets_present:
            reasons.append("password-hashes-exposed-to-cracking")
    elif name == "mimikatz":
        if secrets_present:
            reasons.append("credential-material-present-on-host")
    elif name == "nmap":
        if ports_open:
            reasons.append("open-ports-visible-to-scanning")
        if banner_text.strip():
            reasons.append("version-banners-aid-fingerprinting")
    elif name == "bloodhound":
        if ports_open:
            reasons.append("open-ports-visible-to-scanning")
    elif name == "gobuster":
        if banner_text.strip():
            reasons.append("server-banners-aid-enumeration")
    elif name in ("nikto", "burpsuite", "zaproxy"):
        missing = _missing_security_headers(headers)
        if missing:
            reasons.append(f"missing-security-headers:{','.join(missing)}")
        if banner_text.strip():
            reasons.append("version-banners-disclosed")
        if name in ("burpsuite", "zaproxy") and auth_enforced is False and auth is not None:
            reasons.append("web-surface-without-auth")
    elif name == "sqlmap":
        markers = ("sql", "error", "exception", "odbc", "ora-", "mysql", "syntax")
        if banner_text and any(m in banner_text for m in markers):
            reasons.append("verbose-backend-errors-aid-injection")
    elif name == "wireshark":
        if secrets_present:
            reasons.append("cleartext-sensitive-data-observable")
    elif name == "aircrack-ng":
        markers = ("wep", "wpa", "open", "wps")
        if banner_text and any(m in banner_text for m in markers):
            reasons.append("weak-wireless-configuration-indicated")
    elif name in ("metasploit-framework", "empire"):
        if ports_open and not auth_enforced:
            reasons.append("reachable-service-without-auth")
        if secrets_present:
            reasons.append("secrets-present-on-reachable-host")
    elif name == "responder":
        if ports_open and not auth_enforced:
            reasons.append("name-resolution-spoofing-surface-without-auth")
    elif name in ("netcat", "socat"):
        if ports_open:
            reasons.append("unexpected-egress-or-listener-surface")
    elif name in ("theharvester", "maltego"):
        if secrets_present:
            reasons.append("leaked-credentials-visible-in-public-records")

    if reasons:
        return True, sorted(set(reasons))
    if name in ("john", "hashcat", "mimikatz", "wireshark", "theharvester", "maltego"):
        return False, ["no-credential-or-secret-evidence"]
    return False, ["no-exposure-evidence-in-facts"]


def detect_exposure(tool_name: str, facts: Any) -> ExposureReport:
    """Reason about one tool against caller-supplied facts. Pure logic.

    ``facts`` may carry ``open_ports``, ``banners``, ``auth``,
    ``rate_limit``, ``secrets``, ``headers``; missing keys count as
    unknown and never fire a rule. Raises :class:`ValueError` for
    unknown tool names. Never probes anything.
    """
    tool = get_tool(tool_name)
    fact_dict = dict(facts) if isinstance(facts, dict) else {}
    fact_dict = {str(k).strip().lower(): v for k, v in fact_dict.items()}
    exposed, reasons = _evaluate(tool, fact_dict)
    return ExposureReport(
        tool=tool.name,
        exposed=exposed,
        reasons=tuple(reasons),
        guidance=tool.guidance,
    )


def coverage(tools: Any, emo_capabilities: Any) -> CoverageReport:
    """Compare tool ``detects`` against EMO capabilities, honestly.

    A tool is covered when at least one of its ``detects`` entries
    (case-insensitive) is present in ``emo_capabilities``; every other
    tool lands in ``gaps``. Raises :class:`ValueError` for unknown tool
    names. Deterministic: outputs are sorted.
    """
    names = sorted({(t or "").strip().lower() for t in (tools or ()) if (t or "").strip()})
    for name in names:
        if name not in _BY_NAME:
            raise ValueError(f"unknown kali tool: {name!r}")
    caps = {(c or "").strip().lower() for c in (emo_capabilities or ()) if (c or "").strip()}
    covered = sorted(
        n for n in names if any(d.lower() in caps for d in _BY_NAME[n].detects)
    )
    gaps = sorted(n for n in names if n not in set(covered))
    ratio = (len(covered) / len(names)) if names else 0.0
    return CoverageReport(
        tools=tuple(names),
        capabilities=tuple(sorted(caps)),
        covered=tuple(covered),
        gaps=tuple(gaps),
        coverage_ratio=ratio,
    )


class KaliToolDetectorPack:
    """Facade over the static tool table and pure reasoning functions."""

    table_version: str = TABLE_VERSION

    def all_names(self) -> tuple[str, ...]:
        return all_tool_names()

    def get(self, tool_name: str) -> KaliTool:
        return get_tool(tool_name)

    def detect_exposure(self, tool_name: str, facts: Any) -> ExposureReport:
        return detect_exposure(tool_name, facts)

    def coverage(self, tools: Any, emo_capabilities: Any) -> CoverageReport:
        return coverage(tools, emo_capabilities)
