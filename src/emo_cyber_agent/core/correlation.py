"""Evidence Graph & Security Correlation Foundation — ECA-T008.

FACTS → EVIDENCE → RELATIONSHIPS → CORRELATION → CANDIDATE.
Never: RAW TOOL OUTPUT → LLM → FINAL VULNERABILITY.

This module is ANALYSIS-ONLY. It cannot execute tools, change policy,
touch repositories/databases/network/shell, or issue final Findings.
No Finding object is constructed anywhere in this module (test-pinned).
The LLM has no authority here: SecurityReasonerPort exists as an
interface for ECA-T009, but the engine runs fully without any model.
"""

from __future__ import annotations

import hashlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.core.contracts import EvidenceStore as EvidenceStoreABC
from emo_cyber_agent.domain.models import EvidenceItem

CORRELATION_RULES_VERSION = "corr-v1"
EVIDENCE_SCHEMA_VERSION = "0.1.0"


class EvidenceTrust(StrEnum):
    DETERMINISTIC_TOOL = "deterministic_tool"
    REPOSITORY_FACT = "repository_fact"
    DATABASE_FACT = "database_fact"
    PROVIDER_METADATA = "provider_metadata"
    MODEL_HYPOTHESIS = "model_hypothesis"
    USER_ASSERTION = "user_assertion"


class RelationKind(StrEnum):
    SAME_AS = "same_as"
    DUPLICATE_OF = "duplicate_of"
    LOCATED_IN = "located_in"
    REFERS_TO = "refers_to"
    DEPENDS_ON = "depends_on"
    DERIVED_FROM = "derived_from"
    CONTRADICTS = "contradicts"
    SUPPORTS = "supports"
    CONTEXT_FOR = "context_for"


class ObservationTaxonomy(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INJECTION = "injection"
    SECRETS = "secrets"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    CRYPTOGRAPHY = "cryptography"
    DATA_EXPOSURE = "data_exposure"
    SUPPLY_CHAIN = "supply_chain"
    RLS = "rls"
    API_SECURITY = "api_security"
    BUSINESS_LOGIC = "business_logic"
    INFRASTRUCTURE = "infrastructure"


class CandidateStatus(StrEnum):
    CANDIDATE = "candidate"
    CORRELATED = "correlated"
    NEEDS_VERIFICATION = "needs_verification"
    VERIFYING = "verifying"  # ECA-T010 additive: verification in flight
    SUPPORTED = "supported"
    CONFIRMED = "confirmed"  # ECA-T010 additive: verified-candidate, NOT a final Finding
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"  # ECA-T010 additive
    BLOCKED = "blocked"  # ECA-T010 additive
    PROMOTED = "promoted"  # terminal: handed to a LATER phase via explicit contract


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class EvidenceRelation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: str = Field(..., min_length=1)
    from_id: str = Field(..., min_length=1)
    to_id: str = Field(..., min_length=1)
    kind: RelationKind
    deterministic: bool = True
    reason: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SecurityObservation(BaseModel):
    """A first-pass security-relevant fact. Evidence is mandatory."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: str = Field(..., min_length=1)
    asset_id: str | None = None
    taxonomy: ObservationTaxonomy
    statement: str = Field(..., min_length=1)
    evidence_ids: tuple[str, ...]
    rule_id: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_ids")
    @classmethod
    def _evidence_required(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("observation without evidence is denied")
        return v


class FindingCandidate(BaseModel):
    """A candidate — explicitly NOT a final Finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    candidate_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: str = Field(..., min_length=1)
    asset_id: str | None = None
    observation_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    hypothesis: str = Field(..., min_length=1)
    provisional_severity: str = Field(default="info")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: CandidateStatus = CandidateStatus.CANDIDATE
    rule_id: str = ""
    snapshot_note: str = ""

    @field_validator("evidence_ids")
    @classmethod
    def _evidence_required(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("candidate without evidence is denied")
        return v

    @field_validator("provisional_severity")
    @classmethod
    def _severity(cls, v: str) -> str:
        if v not in ("info", "low", "medium", "high", "critical"):
            raise ValueError("unknown provisional severity")
        return v


class EvidenceConflict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: str = Field(..., min_length=1)
    evidence_ids: tuple[str, ...]
    conflict_type: str = ""
    sources: tuple[str, ...] = ()
    timestamps: tuple[str, ...] = ()
    note: str = ""


class AssetNode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str
    kind: str  # repository | file | endpoint | service | database | table | column | function
    label: str = ""


class AssetEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    frm: str
    to: str
    kind: str  # contains | located_in | depends_on | reads | writes | calls


class AssetGraph(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    nodes: dict[str, AssetNode] = Field(default_factory=dict)
    edges: tuple[AssetEdge, ...] = ()

    def with_node(self, node: AssetNode) -> AssetGraph:
        nodes = dict(self.nodes)
        nodes[node.id] = node
        return AssetGraph(nodes=nodes, edges=self.edges)

    def with_edge(self, edge: AssetEdge) -> AssetGraph:
        return AssetGraph(nodes=self.nodes, edges=(*self.edges, edge))

    def neighbors(self, node_id: str) -> list[str]:
        return [e.to for e in self.edges if e.frm == node_id]


class EvidenceContext(BaseModel):
    """Minimal model-safe context: summaries + provenance only. No secrets, no raw bulk."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str
    candidate_id: str
    summaries: tuple[str, ...] = ()
    provenance: tuple[dict[str, Any], ...] = ()
    locators: tuple[str, ...] = ()
    digests: tuple[str, ...] = ()
    relation_kinds: tuple[str, ...] = ()


class SecurityReasonerPort(ABC):
    """ECA-T009 hook. Proposes hypotheses ONLY; Core never grants it authority.

    The correlation engine below never calls this port. It exists so a
    future reasoner can suggest hypotheses that Core then validates against
    evidence through the same deterministic rules.
    """

    @abstractmethod
    def propose_hypotheses(self, context: EvidenceContext) -> list[str]: ...


# ---------------------------------------------------------------------------
# Deterministic helpers
# ---------------------------------------------------------------------------

def _labels(item: EvidenceItem) -> set[str]:
    raw = item.provenance.get("labels", ()) if isinstance(item.provenance, dict) else ()
    return {str(x) for x in raw}


def _trust(item: EvidenceItem) -> str:
    if isinstance(item.provenance, dict) and item.provenance.get("trust"):
        return str(item.provenance["trust"])
    tool = (item.source_tool or "").lower()
    if tool in ("semgrep", "trivy", "osv-scanner", "gitleaks"):
        return EvidenceTrust.DETERMINISTIC_TOOL.value
    if tool.startswith("github") or tool.startswith("repository"):
        return EvidenceTrust.REPOSITORY_FACT.value
    if tool.startswith("supabase") or tool.startswith("database"):
        return EvidenceTrust.DATABASE_FACT.value
    return EvidenceTrust.PROVIDER_METADATA.value


def dedup_fingerprint(audit_id: str, item: EvidenceItem) -> str:
    """Stable within ONE audit only. Same bytes in another audit never merge."""
    base = "|".join([
        audit_id,
        item.source_tool or "",
        item.source_version or "",
        item.location or "",
        item.content_hash or "",
        item.target_asset_id or "",
    ])
    return hashlib.sha256(base.encode("utf-8", errors="replace")).hexdigest()


def compute_confidence(*, n_evidence: int, n_sources: int, has_conflict: bool) -> float:
    """Deterministic confidence. No model scores, ever."""
    score = 0.2 + 0.2 * min(n_sources, 3) + (0.1 if n_evidence >= 3 else 0.0)
    if has_conflict:
        score -= 0.3
    return round(max(0.05, min(0.95, score)), 2)


CORRELATION_RULES_V1: tuple[dict[str, Any], ...] = (
    {
        "id": "R1-auth-weakness",
        "version": CORRELATION_RULES_VERSION,
        "requires": ("user-controlled-identifier", "db-access", "missing-authorization"),
        "taxonomy": ObservationTaxonomy.AUTHORIZATION.value,
        "hypothesis": "Potential cross-layer authorization weakness: user-controlled identifier reaches data access without authorization evidence",
        "provisional_severity": "high",
        "statement": "Potential cross-layer authorization weakness",
    },
    {
        "id": "R2-vuln-dependency",
        "version": CORRELATION_RULES_VERSION,
        "requires": ("vulnerable-dependency", "package-import"),
        "taxonomy": ObservationTaxonomy.DEPENDENCY.value,
        "hypothesis": "Application imports a package with a known vulnerability",
        "provisional_severity": "medium",
        "statement": "Dependency with known vulnerability is imported",
    },
    {
        "id": "R3-secret-exposure",
        "version": CORRELATION_RULES_VERSION,
        "requires": ("secret-indicator", "tracked-file"),
        "taxonomy": ObservationTaxonomy.SECRETS.value,
        "hypothesis": "Secret indicator present in a tracked file",
        "provisional_severity": "high",
        "statement": "Secret exposure candidate in tracked file",
    },
    {
        "id": "R4-access-control-risk",
        "version": CORRELATION_RULES_VERSION,
        "requires": ("supabase-table", "rls-disabled", "public-grant"),
        "taxonomy": ObservationTaxonomy.RLS.value,
        "hypothesis": "Table without RLS carries a public/authenticated grant (facts only, not a verdict)",
        "provisional_severity": "medium",
        "statement": "Access-control risk facts co-occur on one table",
    },
)

CONTRADICTION_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("rls-enabled", "rls-disabled", "rls-state"),
    ("grant-absent", "public-grant", "grant-state"),
)


# ---------------------------------------------------------------------------
# Evidence Store (Core source of truth for evidence)
# ---------------------------------------------------------------------------

class EvidenceStore(EvidenceStoreABC):
    """Central evidence store. Audit-scoped; cross-audit reads are denied."""

    def __init__(self) -> None:
        self._items: dict[str, EvidenceItem] = {}
        self._audit_of: dict[str, str] = {}
        self._finding_links: dict[str, list[str]] = {}

    # -- contracts.EvidenceStoreABC --
    def store(self, evidence: EvidenceItem, *, audit_id: str = "") -> str:
        if not audit_id:
            raise ValueError("store requires audit_id (evidence stays scope-bound)")
        self._items[evidence.id] = evidence
        self._audit_of[evidence.id] = audit_id
        return evidence.id

    def retrieve(self, evidence_id: str) -> EvidenceItem | None:
        return self._items.get(evidence_id)

    def link_to_finding(self, evidence_id: str, finding_id: str) -> None:
        self._finding_links.setdefault(evidence_id, []).append(finding_id)

    # -- queries (all audit-scoped) --
    def _scoped(self, audit_id: str) -> list[EvidenceItem]:
        return [self._items[eid] for eid, aid in self._audit_of.items() if aid == audit_id]

    def list(self, *, audit_id: str) -> list[EvidenceItem]:
        return self._scoped(audit_id)

    def get(self, evidence_id: str, *, audit_id: str) -> EvidenceItem:
        if self._audit_of.get(evidence_id) != audit_id:
            raise KeyError(f"evidence not in audit scope: {evidence_id}")
        item = self._items.get(evidence_id)
        if item is None:
            raise KeyError(evidence_id)
        return item

    def query(self, *, audit_id: str, asset_id: str | None = None, tool: str | None = None, locator: str | None = None, digest: str | None = None, label: str | None = None) -> list[EvidenceItem]:
        out = []
        for item in self._scoped(audit_id):
            if asset_id is not None and item.target_asset_id != asset_id:
                continue
            if tool is not None and item.source_tool != tool:
                continue
            if locator is not None and item.location != locator:
                continue
            if digest is not None and item.content_hash != digest:
                continue
            if label is not None and label not in _labels(item):
                continue
            out.append(item)
        return out

    def related(self, evidence_id: str, relations: list[EvidenceRelation], *, audit_id: str) -> list[EvidenceItem]:
        ids: set[str] = set()
        for r in relations:
            if r.audit_id != audit_id:
                continue
            if r.from_id == evidence_id:
                ids.add(r.to_id)
            elif r.to_id == evidence_id:
                ids.add(r.from_id)
        return [self.get(i, audit_id=audit_id) for i in ids if i in self._items and self._audit_of.get(i) == audit_id]


# ---------------------------------------------------------------------------
# Correlation Engine (analysis-only: no tools, no policy, no side effects)
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Deterministic correlator. Reads the store, emits relations,
    observations, candidates, conflicts. Writes nothing external."""

    RULES_VERSION = CORRELATION_RULES_VERSION

    def __init__(self, store: EvidenceStore):
        self._store = store
        self._relations: list[EvidenceRelation] = []

    @property
    def relations(self) -> list[EvidenceRelation]:
        return list(self._relations)

    def _relate(self, *, audit_id: str, frm: str, to: str, kind: RelationKind, deterministic: bool, reason: str) -> None:
        self._relations.append(EvidenceRelation(audit_id=audit_id, from_id=frm, to_id=to, kind=kind, deterministic=deterministic, reason=reason))

    def deduplicate(self, *, audit_id: str) -> dict[str, list[str]]:
        """Group evidence by fingerprint WITHIN one audit. Returns fp → ids (len>1)."""
        groups: dict[str, list[str]] = {}
        for item in self._store.list(audit_id=audit_id):
            groups.setdefault(dedup_fingerprint(audit_id, item), []).append(item.id)
        dupes = {fp: ids for fp, ids in groups.items() if len(ids) > 1}
        for ids in dupes.values():
            first, rest = ids[0], ids[1:]
            for other in rest:
                self._relate(audit_id=audit_id, frm=first, to=other, kind=RelationKind.DUPLICATE_OF, deterministic=True, reason="identical fingerprint within audit")
        return dupes

    def detect_conflicts(self, *, audit_id: str) -> list[EvidenceConflict]:
        items = self._store.list(audit_id=audit_id)
        by_locator: dict[str, list[EvidenceItem]] = {}
        for item in items:
            by_locator.setdefault(item.location or "", []).append(item)
        conflicts: list[EvidenceConflict] = []
        for locator, group in by_locator.items():
            present = {label for item in group for label in _labels(item)}
            for left, right, ctype in CONTRADICTION_PAIRS:
                if left in present and right in present:
                    involved = [i for i in group if left in _labels(i) or right in _labels(i)]
                    conflicts.append(
                        EvidenceConflict(
                            audit_id=audit_id,
                            evidence_ids=tuple(i.id for i in involved),
                            conflict_type=ctype,
                            sources=tuple(sorted({i.source_tool for i in involved})),
                            timestamps=tuple(sorted({i.timestamp for i in involved})),
                            note=f"contradictory {ctype} at {locator or '?'}; marked NEEDS_VERIFICATION, never resolved by intuition",
                        )
                    )
                    for i in range(len(involved)):
                        for j in range(i + 1, len(involved)):
                            self._relate(audit_id=audit_id, frm=involved[i].id, to=involved[j].id, kind=RelationKind.CONTRADICTS, deterministic=True, reason=ctype)
        return conflicts

    def build_asset_graph(self, *, audit_id: str) -> AssetGraph:
        graph = AssetGraph()
        for item in self._store.list(audit_id=audit_id):
            if item.target_asset_id and item.target_asset_id not in graph.nodes:
                graph = graph.with_node(AssetNode(id=item.target_asset_id, kind="file", label=item.location or ""))
            if item.location and item.location not in graph.nodes:
                graph = graph.with_node(AssetNode(id=item.location, kind="table" if item.location.startswith("supabase:") or "." in item.location else "file", label=item.location))
            if item.target_asset_id and item.location:
                graph = graph.with_edge(AssetEdge(frm=item.target_asset_id, to=item.location, kind="located_in"))
        return graph

    def correlate(self, *, audit_id: str) -> tuple[list[SecurityObservation], list[FindingCandidate], list[EvidenceConflict]]:
        items = self._store.list(audit_id=audit_id)
        self.deduplicate(audit_id=audit_id)
        conflicts = self.detect_conflicts(audit_id=audit_id)
        conflicted_ids = {eid for c in conflicts for eid in c.evidence_ids}

        observations: list[SecurityObservation] = []
        candidates: list[FindingCandidate] = []
        for rule in CORRELATION_RULES_V1:
            required = set(rule["requires"])
            # group evidence by shared locator-or-asset so rules fire on related facts
            buckets: dict[str, list[EvidenceItem]] = {}
            for item in items:
                buckets.setdefault(item.target_asset_id or item.location or "global", []).append(item)
            for bucket, group in buckets.items():
                have = {label for item in group for label in _labels(item)}
                if not required.issubset(have):
                    continue
                matched = [i for i in group if _labels(i) & required]
                eids = tuple(i.id for i in matched)
                asset = next((i.target_asset_id for i in matched if i.target_asset_id), None)
                stamps = sorted({i.timestamp for i in matched})
                sources = {i.source_tool for i in matched}
                # trust note: model hypotheses never raise confidence
                trusts = {_trust(i) for i in matched}
                obs = SecurityObservation(
                    audit_id=audit_id,
                    asset_id=asset,
                    taxonomy=ObservationTaxonomy(rule["taxonomy"]),
                    statement=str(rule["statement"]),
                    evidence_ids=eids,
                    rule_id=f"{rule['id']}@{rule['version']}",
                    provenance={"trust": sorted(trusts), "sources": sorted(sources)},
                )
                observations.append(obs)
                for i in range(len(matched) - 1):
                    self._relate(audit_id=audit_id, frm=matched[i].id, to=matched[i + 1].id, kind=RelationKind.SUPPORTS, deterministic=True, reason=str(rule["id"]))
                has_conflict = any(i.id in conflicted_ids for i in matched)
                candidates.append(
                    FindingCandidate(
                        audit_id=audit_id,
                        asset_id=asset,
                        observation_ids=(obs.id,),
                        evidence_ids=eids,
                        hypothesis=str(rule["hypothesis"]),
                        provisional_severity=str(rule["provisional_severity"]),
                        confidence=compute_confidence(n_evidence=len(matched), n_sources=len(sources), has_conflict=has_conflict),
                        status=CandidateStatus.NEEDS_VERIFICATION if has_conflict else CandidateStatus.CORRELATED,
                        rule_id=f"{rule['id']}@{rule['version']}",
                        snapshot_note=f"T-context: {stamps[0]}..{stamps[-1]} ({len(stamps)} distinct timestamps; not merged into one instant",
                    )
                )
        return observations, candidates, conflicts


def build_evidence_context(candidate: FindingCandidate, store: EvidenceStore) -> EvidenceContext:
    """Model-safe context: summaries + provenance + locators + digests only.

    Cross-audit reads denied; secrets redacted; raw bulk excluded.
    """
    from emo_cyber_agent.core.repository import redact_credentials

    summaries: list[str] = []
    provs: list[dict[str, Any]] = []
    locators: list[str] = []
    digests: list[str] = []
    for eid in candidate.evidence_ids:
        item = store.get(eid, audit_id=candidate.audit_id)  # raises on cross-audit
        summaries.append(redact_credentials(item.content_summary[:300]))
        provs.append({k: (redact_credentials(str(v))[:200] if isinstance(v, str) else v) for k, v in (item.provenance or {}).items() if k != "raw"})
        if item.location:
            locators.append(item.location)
        if item.content_hash:
            digests.append(item.content_hash)
    return EvidenceContext(
        audit_id=candidate.audit_id,
        candidate_id=candidate.candidate_id,
        summaries=tuple(summaries),
        provenance=tuple(provs),
        locators=tuple(locators),
        digests=tuple(digests),
        relation_kinds=tuple(sorted({r for p in provs for r in (p.get("relation_kinds", []) if isinstance(p, dict) else [])})),
    )
