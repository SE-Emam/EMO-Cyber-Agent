"""Verification strategies — POST-RC-012.

A strategy is a frozen, versioned, provider-independent description
of WHAT must be tested and HOW success, refutation, and
inconclusiveness are recognized. It never executes, never grants a
capability, and never names a vendor executable. Selection is
deterministic: model text may only be untrusted input into a
closed candidate set.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.threat_modeling.spec import canonical_digest
from emo_cyber_agent.verification.adapter_contracts import ADAPTER_CAPABILITIES
from emo_cyber_agent.verification.budget import ResourceBudget
from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode
from emo_cyber_agent.verification.oracles import ORACLE_KINDS

_ID_RE = r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$"

STRATEGY_SCHEMA_VERSION = "1.0"

STRATEGY_CATEGORIES: tuple[str, ...] = (
    "PASSIVE_PROPERTY_CHECK",
    "STATIC_PROPERTY_CHECK",
    "STRUCTURAL_CONSISTENCY",
    "CONFIGURATION_CHECK",
    "AUTHORIZATION_MATRIX",
    "AUTHENTICATION_FLOW",
    "INPUT_BOUNDARY",
    "OUTPUT_BOUNDARY",
    "DATA_FLOW_CONFIRMATION",
    "DEPENDENCY_ASSERTION",
    "SECRET_EXPOSURE_CHECK",
    "NETWORK_BEHAVIOR_CHECK",
    "STATE_CHANGE_CHECK",
    "SAFE_ACTIVE_REQUEST",
    "CONTROLLED_REPRODUCTION",
    "REGRESSION_CHECK",
    "NEGATIVE_TEST",
    "POSITIVE_CONTROL",
)

SAFETY_LEVELS: tuple[str, ...] = ("PASSIVE", "SAFE_ACTIVE", "RESTRICTED_ACTIVE")
_SAFETY_RANK = {level: index for index, level in enumerate(SAFETY_LEVELS)}

# The safety ceiling a category may never exceed, whatever a caller asks.
CATEGORY_SAFETY_CEILING: dict[str, str] = {
    "PASSIVE_PROPERTY_CHECK": "PASSIVE",
    "STATIC_PROPERTY_CHECK": "PASSIVE",
    "STRUCTURAL_CONSISTENCY": "PASSIVE",
    "CONFIGURATION_CHECK": "PASSIVE",
    "DATA_FLOW_CONFIRMATION": "PASSIVE",
    "DEPENDENCY_ASSERTION": "PASSIVE",
    "SECRET_EXPOSURE_CHECK": "PASSIVE",
    "REGRESSION_CHECK": "PASSIVE",
    "AUTHORIZATION_MATRIX": "SAFE_ACTIVE",
    "AUTHENTICATION_FLOW": "SAFE_ACTIVE",
    "INPUT_BOUNDARY": "SAFE_ACTIVE",
    "OUTPUT_BOUNDARY": "SAFE_ACTIVE",
    "NETWORK_BEHAVIOR_CHECK": "SAFE_ACTIVE",
    "STATE_CHANGE_CHECK": "SAFE_ACTIVE",
    "SAFE_ACTIVE_REQUEST": "SAFE_ACTIVE",
    "NEGATIVE_TEST": "SAFE_ACTIVE",
    "POSITIVE_CONTROL": "SAFE_ACTIVE",
    "CONTROLLED_REPRODUCTION": "RESTRICTED_ACTIVE",
}

# Closed target vocabulary. Wildcards and arbitrary destinations do not exist.
TARGET_KINDS: tuple[str, ...] = (
    "FILE",
    "SYMBOL",
    "ROUTE",
    "API_OPERATION",
    "DATABASE_OBJECT",
    "DEPENDENCY",
    "MCP_TOOL",
    "MCP_RESOURCE",
    "AGENT_BOUNDARY",
    "CONFIGURATION",
    "SNAPSHOT",
    # legacy interop with core.verification.TargetKind
    "REPOSITORY",
    "ENDPOINT",
)

FORBIDDEN_TARGET_TOKENS: tuple[str, ...] = ("*", "all", "any", "external_url", "arbitrary_host", "arbitrary_command")

# Vocabulary that must never appear in strategy semantics.
VERDICT_TOKENS: tuple[str, ...] = (
    "vulnerable", "confirmed", "critical", "severity", "exploitable",
    "remediated", "exploit", "fixed", "safe",
)

INPUT_CONTRACTS: tuple[str, ...] = (
    "declared-facts",
    "evidence-reference",
    "bounded-property-value",
    "synthetic-identity-pair",
    "bounded-url-property",
    "bounded-path-fixture",
    "canary-value",
    "structured-tool-result",
    "no-input",
)


class StrategyProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source: str = Field(..., min_length=1, max_length=60)
    origin: str = Field(default="", max_length=160)
    catalog: str = Field(default="", max_length=120)
    schema_version: str = Field(default=STRATEGY_SCHEMA_VERSION, max_length=40)


def assert_no_verdict_tokens(*texts: str) -> None:
    import re as _re

    for text in texts:
        lowered = (text or "").lower()
        for token in VERDICT_TOKENS:
            if _re.search(rf"(?<![\w.:/-]){_re.escape(token)}(?![\w-])", lowered):
                raise StrategyError(StrategyErrorCode.INVALID_STRATEGY, f"verdict vocabulary denied: {token}")


class StrategyTarget(BaseModel):
    """Explicit, snapshot-bound verification target. No wildcards, no
    arbitrary hosts, no arbitrary commands — ever."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: str
    object_identity: str = Field(..., min_length=1, max_length=400)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    locator: str = Field(default="", max_length=400)
    path_parameter: str = Field(default="", max_length=200)
    query_parameter: str = Field(default="", max_length=200)
    body_reference: str = Field(default="", max_length=200)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in TARGET_KINDS:
            raise ValueError(f"target kind not allowed: {v}")
        return v

    @field_validator("object_identity", "locator")
    @classmethod
    def _explicit(cls, v: str) -> str:
        value = (v or "").strip()
        if not value:
            if v == "":
                return v
            raise ValueError("target identity must be explicit")
        lowered = value.lower()
        if value == "*" or lowered in FORBIDDEN_TARGET_TOKENS:
            raise ValueError("wildcard/arbitrary target denied")
        if "\x00" in value:
            raise ValueError("null byte in target")
        if lowered.startswith(("http://", "https://")):
            raise ValueError("external target denied")
        if ".." in value.replace("\\", "/").split("/"):
            raise ValueError("traversal in target denied")
        return value


class VerificationStrategy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str
    version: str
    name: str = Field(..., min_length=1, max_length=160)
    category: str
    applicable_hypotheses: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    allowed_safety_levels: tuple[str, ...] = ("PASSIVE",)
    target_contract: tuple[str, ...] = ()
    input_contract: tuple[str, ...] = ()
    oracle_contract: tuple[str, ...] = ()
    success_criteria: str = Field(..., min_length=1, max_length=500)
    refutation_criteria: str = Field(..., min_length=1, max_length=500)
    limitations: tuple[str, ...] = ()
    resource_budget: ResourceBudget = Field(default_factory=ResourceBudget)
    provenance: StrategyProvenance = Field(default_factory=lambda: StrategyProvenance(source="test"))
    schema_version: str = Field(default=STRATEGY_SCHEMA_VERSION, max_length=40)
    digest: str = Field(default="", max_length=128)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        import re as _re

        if not _re.match(_ID_RE, v):
            raise ValueError("strategy id must be kebab-case")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        import re as _re

        if not _re.match(r"^\d+\.\d+\.\d+$", v):
            raise ValueError("version must be semver X.Y.Z")
        return v

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        if v not in STRATEGY_CATEGORIES:
            raise ValueError(f"strategy category not allowed: {v}")
        return v

    @field_validator("allowed_safety_levels")
    @classmethod
    def _levels(cls, v: tuple[str, ...], info: Any) -> tuple[str, ...]:
        for level in v:
            if level not in SAFETY_LEVELS:
                raise ValueError(f"safety level not allowed: {level}")
        return v

    @field_validator("target_contract", "oracle_contract", "input_contract", "required_capabilities")
    @classmethod
    def _closed(cls, v: tuple[str, ...], info: Any) -> tuple[str, ...]:
        return tuple(dict.fromkeys(v))

    @field_validator("success_criteria", "refutation_criteria")
    @classmethod
    def _criteria(cls, v: str) -> str:
        assert_no_verdict_tokens(v)
        return v

    @field_validator("limitations")
    @classmethod
    def _limitations(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        assert_no_verdict_tokens(*v)
        return v

    def model_post_init(self, __context: Any, /) -> None:
        ceiling = CATEGORY_SAFETY_CEILING[self.category]
        for level in self.allowed_safety_levels:
            if _SAFETY_RANK[level] > _SAFETY_RANK[ceiling]:
                raise ValueError(f"category {self.category} may not allow {level} (ceiling {ceiling})")
        if not self.allowed_safety_levels:
            raise ValueError("strategy must declare at least one safety level")
        for capability in self.required_capabilities:
            if capability not in ADAPTER_CAPABILITIES:
                raise ValueError(f"unknown required capability: {capability}")
        for kind in self.target_contract:
            if kind not in TARGET_KINDS:
                raise ValueError(f"target contract kind not allowed: {kind}")
        for kind in self.oracle_contract:
            if kind not in ORACLE_KINDS:
                raise ValueError(f"oracle contract kind not allowed: {kind}")
        for contract in self.input_contract:
            if contract not in INPUT_CONTRACTS:
                raise ValueError(f"input contract not allowed: {contract}")
        if not self.digest:
            object.__setattr__(self, "digest", self.compute_digest())

    @property
    def max_safety_level(self) -> str:
        return max(self.allowed_safety_levels, key=lambda level: _SAFETY_RANK[level])

    @property
    def safety_ceiling(self) -> str:
        return CATEGORY_SAFETY_CEILING[self.category]

    def allows_safety(self, level: str) -> bool:
        return level in self.allowed_safety_levels

    def supports_target(self, kind: str) -> bool:
        return kind in self.target_contract

    def supports_oracle(self, kind: str) -> bool:
        return kind in self.oracle_contract

    def compute_digest(self) -> str:
        payload = self.model_dump(mode="json", exclude={"digest"})
        return canonical_digest(payload)


def build_strategy(**kwargs: Any) -> VerificationStrategy:
    """Atomic construction: any contract violation raises, leaving no
    partial strategy behind."""
    try:
        return VerificationStrategy(**kwargs)
    except StrategyError:
        raise
    except ValueError as e:
        raise StrategyError(StrategyErrorCode.INVALID_STRATEGY, str(e)) from e


class StrategyCatalog:
    """Deterministic, provenance-checked strategy registry."""

    def __init__(self, strategies: tuple[VerificationStrategy, ...] = ()) -> None:
        self._strategies: dict[tuple[str, str], VerificationStrategy] = {}
        for strategy in strategies:
            self.register(strategy)

    def register(self, strategy: VerificationStrategy) -> None:
        if strategy.provenance.source not in ("official", "starter", "test", "fixture"):
            raise StrategyError(StrategyErrorCode.PROVENANCE_MISSING, f"untrusted provenance: {strategy.provenance.source}")
        key = (strategy.id, strategy.version)
        if key in self._strategies:
            existing = self._strategies[key]
            if existing.digest != strategy.digest:
                raise StrategyError(StrategyErrorCode.CATALOG_INVALID, f"conflicting strategy identity: {strategy.id}@{strategy.version}")
            return
        self._strategies[key] = strategy

    def get(self, strategy_id: str, version: str | None = None) -> VerificationStrategy:
        versions = sorted(
            (v for (sid, v) in self._strategies if sid == strategy_id),
            key=lambda s: [int(p) for p in s.split(".")],
        )
        if not versions:
            raise StrategyError(StrategyErrorCode.ADAPTER_UNKNOWN, f"unknown strategy: {strategy_id}")
        chosen = version if version else versions[-1]
        if (strategy_id, chosen) not in self._strategies:
            raise StrategyError(StrategyErrorCode.ADAPTER_VERSION_MISMATCH, f"unknown strategy version: {strategy_id}@{chosen}")
        return self._strategies[(strategy_id, chosen)]

    def ids(self) -> list[str]:
        return sorted({sid for (sid, _) in self._strategies})

    def all(self) -> list[VerificationStrategy]:
        return [self._strategies[key] for key in sorted(self._strategies)]

    def __len__(self) -> int:
        return len(self._strategies)


def _parse_strategy(raw: dict[str, Any], *, doc_provenance: dict[str, Any]) -> VerificationStrategy:
    budget = raw.pop("resource_budget", {}) or {}
    provenance = {**doc_provenance, **dict(raw.pop("provenance", {}) or {})}
    if provenance.get("source") not in ("official", "starter", "test", "fixture"):
        raise StrategyError(StrategyErrorCode.PROVENANCE_MISSING, "strategy requires explicit provenance source")
    try:
        strategy = build_strategy(
            id=str(raw.get("id", "")),
            version=str(raw.get("version", "")),
            name=str(raw.get("name", "")),
            category=str(raw.get("category", "")),
            applicable_hypotheses=tuple(raw.get("applicable_hypotheses", ()) or ()),
            required_evidence=tuple(raw.get("required_evidence", ()) or ()),
            required_capabilities=tuple(raw.get("required_capabilities", ()) or ()),
            allowed_safety_levels=tuple(raw.get("allowed_safety_levels", ()) or ()),
            target_contract=tuple(raw.get("target_kinds", ()) or ()),
            input_contract=tuple(raw.get("input_contract", ()) or ()),
            oracle_contract=tuple(raw.get("oracle_kinds", ()) or ()),
            success_criteria=str(raw.get("success_criteria", "")),
            refutation_criteria=str(raw.get("refutation_criteria", "")),
            limitations=tuple(raw.get("limitations", ()) or ()),
            resource_budget=ResourceBudget(**{k: int(v) for k, v in budget.items()}),
            provenance=StrategyProvenance(
                source=str(provenance.get("source", "")),
                origin=str(provenance.get("origin", "")),
                catalog=str(provenance.get("catalog", "")),
            ),
        )
    except StrategyError as e:
        if e.code == StrategyErrorCode.INVALID_STRATEGY:
            raise StrategyError(StrategyErrorCode.CATALOG_INVALID, str(e)) from e
        raise
    except (TypeError, ValueError) as e:
        raise StrategyError(StrategyErrorCode.CATALOG_INVALID, str(e)) from e
    if strategy.provenance.source not in ("official", "starter", "test", "fixture"):
        raise StrategyError(StrategyErrorCode.PROVENANCE_MISSING, "strategy requires explicit provenance source")
    return strategy


def load_strategy_file(path: Any) -> tuple[VerificationStrategy, ...]:
    """Read one YAML file. Supports a single `strategy:` mapping or a
    `strategies:` list sharing one document-level provenance block."""
    try:
        import yaml as _yaml
    except ImportError as e:  # pragma: no cover - dependency guard
        raise StrategyError(StrategyErrorCode.CATALOG_INVALID, "YAML parsing needs pyyaml") from e

    try:
        doc = _yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        raise StrategyError(StrategyErrorCode.CATALOG_INVALID, f"malformed strategy YAML: {e}") from e
    if not isinstance(doc, dict):
        raise StrategyError(StrategyErrorCode.CATALOG_INVALID, "strategy YAML must be a mapping")
    doc_provenance = dict(doc.get("provenance") or {})
    if "strategies" in doc:
        entries = doc["strategies"]
        if not isinstance(entries, list) or not entries:
            raise StrategyError(StrategyErrorCode.CATALOG_INVALID, "strategies must be a non-empty list")
        return tuple(_parse_strategy(dict(entry), doc_provenance=doc_provenance) for entry in entries)
    if "strategy" not in doc or not isinstance(doc["strategy"], dict):
        raise StrategyError(StrategyErrorCode.CATALOG_INVALID, "strategy YAML must contain a top-level strategy mapping")
    return (_parse_strategy(dict(doc["strategy"]), doc_provenance=doc_provenance),)


def load_strategy(path: Any) -> VerificationStrategy:
    strategies = load_strategy_file(path)
    if len(strategies) != 1:
        raise StrategyError(StrategyErrorCode.CATALOG_INVALID, f"expected exactly one strategy in {path}, found {len(strategies)}")
    return strategies[0]


def load_official_strategies(directory: Any) -> StrategyCatalog:
    paths = sorted(Path(directory).glob("*.yaml"))
    if not paths:
        raise StrategyError(StrategyErrorCode.CATALOG_INVALID, f"no strategies in {directory}")
    catalog = StrategyCatalog()
    for path in paths:
        for strategy in load_strategy_file(path):
            if strategy.provenance.source != "official":
                raise StrategyError(StrategyErrorCode.PROVENANCE_MISSING, f"official strategy lacks official provenance: {strategy.id}")
            catalog.register(strategy)
    if len(catalog) == 0:
        raise StrategyError(StrategyErrorCode.CATALOG_INVALID, f"no strategies in {directory}")
    return catalog
