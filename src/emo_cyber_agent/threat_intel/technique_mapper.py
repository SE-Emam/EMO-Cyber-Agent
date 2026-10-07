"""MITRE ATT&CK technique knowledge — DEFENSIVE KNOWLEDGE ONLY.

A curated, static table mapping defensive finding signals (CWE
references, keywords, finding categories) to ATT&CK technique ids.
Technique records carry defender-oriented descriptions, the tool names
known to abuse each technique (*knowledge, not usage*), and detection
guidance.

Non-negotiable boundaries:

- Nothing here executes, exploits, scans live targets, or crawls.
- Unknown signals map to an empty list: ids are never hallucinated.
  Every returned id is validated against the static table.
- No randomness, no clock, no network: ranking is a deterministic
  function of the inputs (exact CWE hit outranks keyword hits; ties
  break by technique id).

Shape reuses frozen-pydantic conventions (``frozen=True``,
``extra="forbid"``, ``to_dict`` / ``from_dict`` /
``to_canonical_json``).
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "TABLE_VERSION",
    "VALID_TACTICS",
    "TECHNIQUES",
    "AttackTechnique",
    "TechniqueRef",
    "AttackTechniqueMapper",
    "all_technique_ids",
    "get_technique",
    "technique_known",
    "map_finding",
]

TABLE_VERSION = "1.0.0"

VALID_TACTICS: tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_CWE_RE = re.compile(r"^CWE-\d+$")


class AttackTechnique(BaseModel):
    """One curated defensive technique record. Data only — never executed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(...)
    tactic: str = Field(...)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    kali_tools: tuple[str, ...] = Field(min_length=1)
    detection_guidance: str = Field(min_length=1, max_length=2000)
    cwe_refs: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        text = (v or "").strip().upper()
        if not _ID_RE.match(text):
            raise ValueError("technique id must look like T1234 or T1234.001")
        return text

    @field_validator("tactic")
    @classmethod
    def _tactic(cls, v: str) -> str:
        if v not in VALID_TACTICS:
            raise ValueError(f"unknown tactic: {v!r}")
        return v

    @field_validator("cwe_refs")
    @classmethod
    def _cwes(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for cwe in v:
            if not _CWE_RE.match((cwe or "").strip().upper()):
                raise ValueError(f"cwe ref must look like CWE-123: {cwe!r}")
        return tuple((c or "").strip().upper() for c in v)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class TechniqueRef(BaseModel):
    """One ranked mapping hit. ``basis`` explains why it was selected."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str = Field(...)
    basis: Literal["cwe", "keyword"] = Field(...)
    score: float = Field(ge=0.0)

    @field_validator("technique_id")
    @classmethod
    def _id(cls, v: str) -> str:
        text = (v or "").strip().upper()
        if not _ID_RE.match(text):
            raise ValueError("technique id must look like T1234 or T1234.001")
        return text

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _t(
    tid: str,
    tactic: str,
    name: str,
    description: str,
    kali_tools: tuple[str, ...],
    detection_guidance: str,
    cwe_refs: tuple[str, ...],
) -> AttackTechnique:
    return AttackTechnique(
        id=tid,
        tactic=tactic,
        name=name,
        description=description,
        kali_tools=kali_tools,
        detection_guidance=detection_guidance,
        cwe_refs=cwe_refs,
    )


TECHNIQUES: tuple[AttackTechnique, ...] = (
    _t(
        "T1595", "Reconnaissance", "Active Scanning",
        "Defenders should assume externally reachable services are fingerprinted before any "
        "attack: scanning reveals open ports, banners, and web paths that later stages reuse.",
        ("nmap", "nikto", "gobuster", "theharvester"),
        "Alert on repeated connection sweeps and path enumeration from few sources; inventory "
        "exposed ports and banners so unexpected services are noticed.",
        ("CWE-200",),
    ),
    _t(
        "T1190", "Initial Access", "Exploit Public-Facing Application",
        "Public web inputs that reach interpreters, queries, or deserializers let attackers in "
        "without credentials; defenders treat every public parameter as untrusted.",
        ("metasploit-framework", "sqlmap", "burpsuite", "nikto", "zaproxy"),
        "Monitor WAF and application logs for injection payloads and deserialization errors; "
        "patch public components and fuzz inputs in staging.",
        ("CWE-20", "CWE-89", "CWE-502"),
    ),
    _t(
        "T1078", "Persistence", "Valid Accounts",
        "Stolen or default credentials bypass perimeter controls entirely; defenders focus on "
        "credential hygiene and anomalous use of legitimate accounts.",
        ("hydra", "mimikatz", "empire"),
        "Baseline normal logon times and hosts per account; alert on impossible travel, dormant "
        "account reuse, and default-credential logons.",
        ("CWE-287", "CWE-798"),
    ),
    _t(
        "T1003", "Credential Access", "OS Credential Dumping",
        "Memory and registry stores of credentials are a prime target once code runs on a host; "
        "defenders harden LSASS-equivalents and credential caches.",
        ("mimikatz", "empire", "hashcat"),
        "Alert on access to credential stores and suspicious process memory reads; enforce "
        "Credential Guard-style protections and short-lived credentials.",
        ("CWE-312",),
    ),
    _t(
        "T1059", "Execution", "Command and Scripting Interpreter",
        "Shells and scripting runtimes turn small footholds into full control; defenders "
        "constrain which interpreters exist and who may invoke them.",
        ("metasploit-framework", "empire", "netcat", "socat"),
        "Log command lines and script-block activity; alert on encoded payloads, LOLBins, and "
        "interpreters spawned by web or office processes.",
        ("CWE-78",),
    ),
    _t(
        "T1021", "Lateral Movement", "Remote Services",
        "Valid network logons to RDP/SSH/SMB-class services move attackers host to host; "
        "defenders segment networks and require jump hosts with MFA.",
        ("metasploit-framework", "netcat", "socat", "bloodhound"),
        "Alert on first-time admin logons to new hosts and lateral logon chains; review remote "
        "service exposure and privileged session recordings.",
        ("CWE-287",),
    ),
    _t(
        "T1110", "Credential Access", "Brute Force",
        "Online password guessing succeeds wherever authentication lacks throttling; defenders "
        "treat missing rate limits and lockouts as the core exposure.",
        ("hydra", "john", "hashcat", "burpsuite"),
        "Alert on authentication-failure bursts per account and source; require rate limiting, "
        "lockout or progressive delays, and MFA on all remote logons.",
        ("CWE-307", "CWE-521"),
    ),
    _t(
        "T1552", "Credential Access", "Unsecured Credentials",
        "Passwords, keys, and tokens left in files, configs, or histories are collected without "
        "any exploit; defenders scan for and vault all embedded secrets.",
        ("mimikatz", "theharvester", "responder"),
        "Scan repositories, configs, and histories for secret patterns; alert on access to "
        "known credential files and rotate exposed material.",
        ("CWE-798", "CWE-312"),
    ),
    _t(
        "T1530", "Collection", "Data from Cloud Storage",
        "Public or over-shared buckets and drives leak data without touching the network "
        "perimeter; defenders inventory sharing posture continuously.",
        ("theharvester", "maltego"),
        "Audit bucket policies and sharing links for world-readable data; alert on anonymous "
        "access to storage and mass-download patterns.",
        ("CWE-200",),
    ),
    _t(
        "T1204", "Execution", "User Execution",
        "Malicious attachments and links still need a user click; defenders combine attachment "
        "sandboxing with user reporting drills.",
        ("metasploit-framework", "empire"),
        "Detonate attachments and links in sandboxes; alert on first-seen droppers and macro "
        "execution from mail clients.",
        ("CWE-434",),
    ),
    _t(
        "T1566", "Initial Access", "Phishing",
        "Deceptive messages deliver access with no technical vulnerability; defenders filter, "
        "quarantine, and rehearse reporting.",
        ("theharvester", "maltego", "empire"),
        "Alert on lookalike-domain mail, credential-harvest URLs, and attachment bursts; track "
        "report-to-click ratios per campaign.",
        ("CWE-451",),
    ),
    _t(
        "T1048", "Exfiltration", "Exfiltration Over Alternative Protocol",
        "DNS, ICMP, or raw-socket channels move data past HTTP-focused inspection; defenders "
        "watch volume and entropy on non-standard egress.",
        ("netcat", "socat", "wireshark"),
        "Alert on unusual DNS query volume, ICMP payload size, and long-lived non-HTTP egress "
        "flows; whitelist expected egress protocols per host.",
        ("CWE-200",),
    ),
    _t(
        "T1071", "Command and Control", "Application Layer Protocol",
        "C2 over common web or mail protocols blends into normal traffic; defenders look for "
        "beaconing regularity rather than protocol alone.",
        ("netcat", "socat", "empire", "wireshark"),
        "Alert on periodic egress to rare destinations and mismatched protocol fingerprints "
        "(for example HTTP without a browser stack).",
        ("CWE-300",),
    ),
    _t(
        "T1499", "Impact", "Endpoint Denial of Service",
        "Resource-exhaustion floods deny service without breaching data; defenders plan "
        "rate-based shedding and upstream filtering.",
        ("metasploit-framework", "netcat"),
        "Alert on traffic and request-rate anomalies per endpoint; keep per-client budgets and "
        "tested upstream scrubbing runbooks.",
        ("CWE-400",),
    ),
    _t(
        "T1133", "Initial Access", "External Remote Services",
        "Internet-facing remote-access services are password-sprayed and exploited directly; "
        "defenders gate them behind MFA and allow-lists.",
        ("nmap", "metasploit-framework", "bloodhound"),
        "Alert on logons to VPN/RDP-class gateways from new ASNs; require MFA plus device "
        "posture before remote access.",
        ("CWE-287",),
    ),
    _t(
        "T1098", "Persistence", "Account Manipulation",
        "Quiet changes to existing accounts (groups, keys, MFA removal) persist access; "
        "defenders audit every privilege or recovery change.",
        ("mimikatz", "empire", "bloodhound"),
        "Alert on group-membership, SSH-key, and MFA-policy changes outside change windows; "
        "reconcile privileged rosters regularly.",
        ("CWE-732",),
    ),
    _t(
        "T1136", "Persistence", "Create Account",
        "New local or domain accounts are a classic backdoor; defenders watch account-creation "
        "events on every identity store.",
        ("empire", "metasploit-framework"),
        "Alert on account creation outside provisioning workflows, especially privileged or "
        "hidden accounts; auto-expire test accounts.",
        ("CWE-732",),
    ),
    _t(
        "T1090", "Command and Control", "Proxy",
        "Single-hop and relay proxies hide C2 origins; defenders flag hosts whose traffic is "
        "disproportionately forwarded.",
        ("socat", "netcat", "empire"),
        "Alert on unexpected listening forwarders and external proxy tools on servers; "
        "correlate inbound and outbound sessions per host.",
        ("CWE-300",),
    ),
    _t(
        "T1573", "Command and Control", "Encrypted Channel",
        "Standard TLS carrying C2 defeats payload inspection; defenders rely on metadata, "
        "certificates, and endpoint visibility instead.",
        ("socat", "netcat", "wireshark"),
        "Alert on JA3/JA4 anomalies, self-signed or fresh certificates, and TLS to rare "
        "destinations; keep endpoint process-to-flow attribution.",
        ("CWE-310",),
    ),
    _t(
        "T1557", "Credential Access", "Adversary-in-the-Middle",
        "Network-position attacks downgrade or relay authentication; defenders enforce signed, "
        "encrypted protocols and reject legacy fallbacks.",
        ("responder", "wireshark", "aircrack-ng"),
        "Alert on LLMNR/NBT-NS-style spoofing, unexpected ARP/ND changes, and NTLM relay "
        "patterns; enforce SMB signing and LDAP channel binding.",
        ("CWE-300", "CWE-294"),
    ),
    _t(
        "T1486", "Impact", "Data Encrypted for Impact",
        "Ransomware-style encryption destroys availability after access is already won; "
        "defenders invest in offline backups and bulk-rename detection.",
        ("metasploit-framework",),
        "Alert on mass file-renames, shadow-copy deletion, and backup tampering; rehearse "
        "offline restore, not ransom payment.",
        ("CWE-693",),
    ),
    _t(
        "T1490", "Impact", "Inhibit System Recovery",
        "Deleting backups and recovery state precedes the visible impact; defenders treat any "
        "backup tampering as a critical precursor.",
        ("metasploit-framework", "empire"),
        "Alert on backup-service stops, recovery-catalog edits, and safe-mode/boot changes; "
        "keep immutable, tested offline copies.",
        ("CWE-693",),
    ),
    _t(
        "T1083", "Discovery", "File and Directory Discovery",
        "Content and share enumeration finds the sensitive paths worth stealing; defenders "
        "shrink listings and watch enumeration patterns.",
        ("gobuster", "nikto", "bloodhound"),
        "Alert on directory-brute-force patterns and 404/403 bursts; remove verbose listings "
        "and predictable backup paths.",
        ("CWE-200",),
    ),
    _t(
        "T1018", "Discovery", "Remote System Discovery",
        "Host and share discovery maps the flat network for lateral moves; defenders segment "
        "and alert on sweep behavior from workstations.",
        ("nmap", "bloodhound"),
        "Alert on ARP/scan sweeps and share-enumeration from non-admin hosts; keep network "
        "maps current so rogue hosts stand out.",
        ("CWE-200",),
    ),
)

_BY_ID: dict[str, AttackTechnique] = {t.id: t for t in TECHNIQUES}

_CWE_INDEX: dict[str, list[str]] = {}
for _tech in TECHNIQUES:
    for _cwe in _tech.cwe_refs:
        _CWE_INDEX.setdefault(_cwe, []).append(_tech.id)
for _ids in _CWE_INDEX.values():
    _ids.sort()

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

# Function words carry no technique signal and match noisily as
# substrings ("not" hits "notice"/"cannot"); they are dropped from
# keyword matching. Content words are never filtered.
_STOPWORDS: frozenset[str] = frozenset(
    {"the", "and", "are", "was", "were", "has", "have", "had", "will", "would",
     "can", "could", "shall", "should", "may", "might", "must", "not", "nor",
     "for", "with", "from", "that", "this", "these", "those", "they", "them",
     "their", "there", "here", "what", "when", "where", "which", "while",
     "whom", "whose", "your", "about", "after", "before", "being", "does",
     "doing", "done", "down", "just", "like", "many", "much", "same", "such",
     "than", "then", "also", "into", "over", "under", "both", "each", "few",
     "more", "most", "other", "some", "very", "well", "whether"}
)


def _normalize_cwe(cwe: Any) -> str:
    text = str(cwe or "").strip().upper()
    if re.match(r"^\d+$", text):
        text = f"CWE-{text}"
    return text


def _tokens(category: Any, keywords: Any) -> tuple[str, ...]:
    raw: list[str] = []
    if category:
        raw.extend(_TOKEN_SPLIT_RE.split(str(category).lower()))
    if isinstance(keywords, str):
        raw.extend(_TOKEN_SPLIT_RE.split(keywords.lower()))
    else:
        for item in keywords or ():
            raw.extend(_TOKEN_SPLIT_RE.split(str(item).lower()))
    seen: set[str] = set()
    ordered: list[str] = []
    for token in raw:
        token = token.strip()
        if len(token) >= 3 and token not in seen and token not in _STOPWORDS:
            seen.add(token)
            ordered.append(token)
    return tuple(ordered)


def all_technique_ids() -> tuple[str, ...]:
    """Sorted ids of every technique in the static table."""
    return tuple(sorted(_BY_ID))


def get_technique(technique_id: str) -> AttackTechnique:
    """Return the table record for a known id; raise ValueError otherwise."""
    key = (technique_id or "").strip().upper()
    try:
        return _BY_ID[key]
    except KeyError:
        raise ValueError(f"unknown technique id: {technique_id!r}") from None


def technique_known(technique_id: str) -> bool:
    """Validator: True only for ids present in the static table."""
    return (technique_id or "").strip().upper() in _BY_ID


def map_finding(
    category: Any = None,
    cwe: Any = None,
    keywords: Any = (),
) -> list[TechniqueRef]:
    """Map defensive signals to ranked technique references.

    Tier 1 (``basis="cwe"``, ``score=1.0``): the normalized CWE
    (``"798"`` and ``"CWE-798"`` are equivalent) exactly matches a
    technique's ``cwe_refs``. Tier 2 (``basis="keyword"``): distinct
    query tokens (from ``keywords`` plus ``category`` word-splits of
    length >= 3, minus English function-word stopwords) found as
    substrings in the technique's name, description, guidance, and
    tactic; ``score`` is the count of distinct matched tokens. Tier 1
    sorts before tier 2; within a tier, higher score then lower
    technique id wins. Unknown signals yield ``[]`` — ids are never
    invented.
    """
    hits: list[TechniqueRef] = []
    cwe_key = _normalize_cwe(cwe) if cwe else ""
    if cwe_key and _CWE_RE.match(cwe_key):
        for tid in _CWE_INDEX.get(cwe_key, ()):
            hits.append(TechniqueRef(technique_id=tid, basis="cwe", score=1.0))
    tokens = _tokens(category, keywords)
    if tokens:
        scored: list[tuple[float, str]] = []
        for tech in TECHNIQUES:
            haystack = " ".join(
                (tech.name, tech.description, tech.detection_guidance, tech.tactic)
            ).lower()
            count = sum(1 for token in tokens if token in haystack)
            if count:
                scored.append((float(count), tech.id))
        scored.sort(key=lambda item: (-item[0], item[1]))
        for count, tid in scored:
            hits.append(TechniqueRef(technique_id=tid, basis="keyword", score=count))
    return hits


class AttackTechniqueMapper:
    """Facade over the static technique table and :func:`map_finding`."""

    table_version: str = TABLE_VERSION

    def all_ids(self) -> tuple[str, ...]:
        return all_technique_ids()

    def get(self, technique_id: str) -> AttackTechnique:
        return get_technique(technique_id)

    def known(self, technique_id: str) -> bool:
        return technique_known(technique_id)

    def map_finding(
        self, category: Any = None, cwe: Any = None, keywords: Any = ()
    ) -> list[TechniqueRef]:
        return map_finding(category, cwe, keywords)
