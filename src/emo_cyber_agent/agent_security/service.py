"""Agent security service — POST-RC-010.

Core-owned orchestration: declared architecture → system model →
capability graph → attack surface → MCP topology → analyses →
scenarios → controls → handoffs → evidence → report view.
Read-only, deterministic, planning-only. No model calls, no
tool execution, no Finding creation, no confirmation.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.agent_security.agent_model import build_agent_system
from emo_cyber_agent.agent_security.attack_surface import build_agent_attack_surface
from emo_cyber_agent.agent_security.credential_analysis import analyze_credential_flows
from emo_cyber_agent.agent_security.delegation import analyze_delegations
from emo_cyber_agent.agent_security.errors import AgentSecurityError, AgentSecurityErrorCode
from emo_cyber_agent.agent_security.mcp_model import build_mcp_topology
from emo_cyber_agent.agent_security.memory_analysis import analyze_retrieval_trust, check_memory_isolation
from emo_cyber_agent.agent_security.provenance import build_agent_provenance
from emo_cyber_agent.agent_security.scope_analysis import build_capability_graph, detect_excessive_agency, detect_scope_widening
from emo_cyber_agent.agent_security.spec import (
    AgentSecurityControl,
    AgentSecurityObservation,
    AgentThreatScenario,
)
from emo_cyber_agent.agent_security.tool_poisoning import analyze_tool_misuse, analyze_tool_poisoning
from emo_cyber_agent.threat_modeling.spec import canonical_digest, stable_id

# Volatile operational metadata excluded from deterministic identity.
_VOLATILE_KEYS = {"observed_at", "timestamp", "captured_at", "created_at"}


def _stable(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {k: _stable(v) for k, v in payload.items() if k not in _VOLATILE_KEYS}
    if isinstance(payload, list):
        return [_stable(v) for v in payload]
    return payload


# Deterministic agent-skill → existing security-pack mapping.
# Packs are methodology, never authority.
SKILL_PACK_MAP: dict[str, tuple[str, ...]] = {
    "mcp-security": ("ssrf-request-forgery", "injection-security"),
    "agent-security": ("authentication-authorization", "injection-security"),
    "ai-security": ("injection-security",),
    "injection": ("injection-security", "ssrf-request-forgery", "xss-output-encoding", "path-traversal-file-access"),
    "authentication": ("authentication-authorization",),
    "authorization": ("authentication-authorization",),
    "secrets": ("secrets-sensitive-data",),
    "api-security": ("ssrf-request-forgery", "authentication-authorization"),
    "backend-security": ("injection-security", "path-traversal-file-access"),
    "frontend-security": ("xss-output-encoding",),
    "dependency-security": ("dependency-supply-chain",),
    "supply-chain": ("dependency-supply-chain",),
    "configuration": ("security-configuration",),
    "threat-modeling": (),
}

# Deterministic change-signal → agent review trigger mapping.
CHANGE_TRIGGERS: dict[str, tuple[str, ...]] = {
    "AUTH_BOUNDARY_CHANGED": ("authorization-review",),
    "NEW_EXTERNAL_INPUT": ("injection-review",),
    "STATE_CHANGE_ADDED": ("authorization-review",),
    "NEW_DATA_STORE_RELATION": ("database-review",),
    "DEPENDENCY_VERSION_CHANGED": ("supply-chain-review",),
    "SKILL_CHANGED": ("skill-review",),
    "SYSTEM_PROMPT_CHANGED": ("injection-review",),
    "DELEGATION_POLICY_CHANGED": ("delegation-review",),
    "MEMORY_SOURCE_CHANGED": ("poisoning-review",),
}


class AgentSecurityAssessment:
    """Immutable assessment snapshot. Attribute holder, not a model."""

    def __init__(self, *, system: Any, surface: Any, capability_graph: Any, mcp_topology: Any, scenarios: Any, controls: Any, handoffs: Any, observations: Any, signals: Any, digest: str, limitations: Any, methods: Any = ()):
        self.system = system
        self.surface = surface
        self.capability_graph = capability_graph
        self.mcp_topology = mcp_topology
        self.scenarios = scenarios
        self.controls = controls
        self.handoffs = handoffs
        self.observations = observations
        self.signals = signals
        self.digest = digest
        self.limitations = limitations
        self.methods = methods

    @property
    def audit_id(self) -> str:
        return self.system.audit_id

    @property
    def snapshot_id(self) -> str:
        return self.system.snapshot_id


class AgentSecurityService:
    def __init__(self, *, max_paths: int = 25):
        self._max_paths = max_paths

    def analyze(
        self,
        *,
        audit_id: str,
        project_id: str = "",
        snapshot_id: str = "",
        architecture: dict[str, Any] | None = None,
        skill_capabilities: dict[str, tuple[str, ...]] | None = None,
        tool_capabilities: dict[str, tuple[str, ...]] | None = None,
        policy_grants: dict[str, tuple[str, ...]] | None = None,
        task_scope: tuple[str, ...] = (),
        description_samples: dict[str, str] | None = None,
        output_samples: dict[str, str] | None = None,
        retrieval_samples: dict[str, str] | None = None,
        allowed_tools: dict[str, tuple[str, ...]] | None = None,
    ) -> AgentSecurityAssessment:
        architecture = architecture or {}
        system = build_agent_system(audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id, **{k: tuple(v) for k, v in architecture.items()})
        capability_graph = build_capability_graph(system, skill_capabilities=skill_capabilities, tool_capabilities=tool_capabilities, policy_grants=policy_grants)
        surface = build_agent_attack_surface(system)
        mcp_topology = build_mcp_topology(system)
        signals = self._signals(system, task_scope=task_scope, description_samples=description_samples or {}, output_samples=output_samples or {}, retrieval_samples=retrieval_samples or {}, allowed_tools=allowed_tools or {}, policy_grants=policy_grants or {})
        scenarios = self._scenarios(system, signals)
        controls = self._controls(system)
        from emo_cyber_agent.agent_security.verification import handoffs_for_scenarios as _handoffs

        handoffs = _handoffs(tuple(scenarios), snapshot_id=snapshot_id)
        observations = self._observations(system, signals)
        limitations = list(system.limitations) + list(surface.limitations) + list(mcp_topology.get("limitations", ()))
        digest = canonical_digest({
            "audit": audit_id, "project": project_id, "snapshot": snapshot_id,
            "system": _stable(system.model_dump(mode="json", exclude={"limitations"})),
            "surface": [_stable(e.model_dump(mode="json")) for e in surface.elements],
            "scenarios": [s.model_dump(mode="json") for s in scenarios],
            "controls": [c.model_dump(mode="json") for c in controls],
        })
        return AgentSecurityAssessment(
            system=system, surface=surface, capability_graph=capability_graph, mcp_topology=mcp_topology,
            scenarios=tuple(scenarios), controls=tuple(controls), handoffs=tuple(handoffs),
            observations=tuple(observations), signals=tuple(signals), digest=digest,
            limitations=tuple(limitations),
        )

    def _signals(self, system: Any, *, task_scope: tuple[str, ...], description_samples: dict[str, str], output_samples: dict[str, str], retrieval_samples: dict[str, str], allowed_tools: dict[str, tuple[str, ...]], policy_grants: dict[str, tuple[str, ...]]) -> list[dict[str, Any]]:
        from emo_cyber_agent.agent_security.prompt_analysis import PRIVILEGED_SINK_KINDS, analyze_prompt_injection

        signals: list[dict[str, Any]] = []
        privileged = [t for t in system.mcp_tools] + [s for s in system.tool_bindings]
        sink_shapes = tuple({"sink_id": getattr(t, "tool_id", ""), "kind": "mcp-call" if hasattr(t, "server_id") else "tool-call"} for t in privileged)
        source_shapes = tuple(system.context_sources) + tuple(system.prompt_sources) + tuple(system.retrieval_sources) + tuple(system.memories)
        signals.extend(analyze_prompt_injection(source_shapes, sink_shapes))
        signals.extend(analyze_tool_poisoning(tuple(system.mcp_tools), description_samples=description_samples, output_samples=output_samples))
        signals.extend(analyze_tool_misuse(tuple(system.tool_bindings), allowed=allowed_tools))
        signals.extend(analyze_delegations(system))
        signals.extend(check_memory_isolation(tuple(system.memories)))
        signals.extend(analyze_retrieval_trust(tuple(system.retrieval_sources), content_samples=retrieval_samples))
        signals.extend(analyze_credential_flows(tuple(system.credential_flows), boundaries=tuple(system.credential_boundaries)))
        declared = list(task_scope)
        effective: list[str] = []
        for holder, caps in (policy_grants or {}).items():
            effective.extend(f"{holder}:{c}" for c in caps)
        signals.extend(detect_scope_widening(tuple(declared), tuple(sorted(set(effective)))))
        reachable = [c.split(":", 1)[-1] for c in effective]
        tool_caps: list[str] = []
        for binding in system.tool_bindings:
            tool_caps.append(binding.tool_id)
        signals.extend(detect_excessive_agency(tuple(task_scope), tuple(sorted(set(reachable + tool_caps)))))
        _ = PRIVILEGED_SINK_KINDS
        return signals

    def _scenarios(self, system: Any, signals: list[dict[str, Any]]) -> list[AgentThreatScenario]:
        from emo_cyber_agent.agent_security import threat_rules as _rules
        from emo_cyber_agent.agent_security.taxonomy import categories as _categories
        from emo_cyber_agent.agent_security.taxonomy import framework_mapping as _framework_mapping

        seeds: list[dict[str, Any]] = []
        seeds.extend(_rules.rule_unprotected_state_changes(system, self._surface_of(system)))
        seeds.extend(_rules.rule_untrusted_context_to_privileged_tool(system))
        seeds.extend(_rules.rule_credential_reach(system))
        seeds.extend(_rules.rule_delegation_widening(tuple(signals)))
        seeds.extend(_rules.rule_memory_poisoning(tuple(signals)))
        seeds.extend(_rules.rule_tool_poisoning(tuple(signals)))
        seeds.extend(_rules.rule_scope_signals(tuple(signals)))
        scenarios: list[AgentThreatScenario] = []
        seen: set[str] = set()
        for seed in sorted(seeds, key=lambda s: (str(s.get("category", "")), str(s.get("subject", "")))):
            category = str(seed.get("category", "TOOL_MISUSE"))
            if category not in _categories():
                continue
            scenario_id = stable_id("agent-threat", category, str(seed.get("subject", "subject")))
            if scenario_id in seen:
                continue
            seen.add(scenario_id)
            evidence = ("surface-record",)
            scenarios.append(AgentThreatScenario(
                scenario_id=scenario_id, category=category, source=str(seed.get("subject", ""))[:320],
                target="", trust_boundaries=(), affected_agents=(), affected_tools=(), affected_assets=(),
                preconditions=(str(seed.get("attack_goal", ""))[:500],) if seed.get("attack_goal") else (),
                attack_sequence=("untrusted-input to context ingestion", f"context influence on {seed.get('subject', 'target')}", "privileged action", "sensitive output") if category in ("PROMPT_INJECTION", "INDIRECT_PROMPT_INJECTION") else (),
                evidence_ids=evidence, hypothesis_status="SUPPORTED_BY_EVIDENCE",
                verification_requirements=("static_confirmation",),
                coverage="PARTIALLY_MAPPED",
                limitations=tuple(seed.get("limitations", ("model-decision step unverified",))),
                framework_mappings=_framework_mapping(category),
            ))
        return scenarios

    def _surface_of(self, system: Any) -> Any:
        from emo_cyber_agent.agent_security.attack_surface import build_agent_attack_surface

        return build_agent_attack_surface(system)

    def _controls(self, system: Any) -> list[AgentSecurityControl]:
        controls: list[AgentSecurityControl] = []
        for index, boundary in enumerate(sorted(system.boundaries, key=lambda b: b.boundary_id)):
            controls.append(AgentSecurityControl(
                control_id=f"agent-control-{index:03d}", kind="CAPABILITY_SCOPING", status="OBSERVED_CONTROL",
                protects=tuple(boundary.protects), provenance={"boundary_id": boundary.boundary_id},
            ))
        return controls

    def _observations(self, system: Any, signals: list[dict[str, Any]]) -> list[Any]:

        observations = []
        for index, signal in enumerate(sorted(signals, key=lambda s: (s.get("signal", ""), str(s.get("detail", ""))[:80]))):
            observations.append(AgentSecurityObservation(
                observation_id=f"agent-observation-{index + 1:03d}", kind=str(signal.get("signal", "SIGNAL")),
                statement=f"{signal.get('signal', 'signal')}: {signal.get('detail', '')}"[:1000],
                evidence_ids=("surface-record",),
                provenance=build_agent_provenance(audit_id=system.audit_id, project_id=system.project_id, snapshot_id=system.snapshot_id, subject_id=str(signal.get("delegation_id", signal.get("tool_id", signal.get("source_id", "signal"))))),
            ))
        return observations

    def select_methods_for_skills(self, skills: tuple[str, ...]) -> tuple[str, ...]:
        table: dict[str, tuple[str, ...]] = {
            "authorization": ("stride", "attack-tree"),
            "authentication": ("stride",),
            "api-security": ("stride", "data-centric"),
            "injection": ("stride", "data-centric"),
            "backend-security": ("stride", "data-centric"),
            "threat-modeling": ("stride", "attack-tree", "data-centric"),
            "mcp-security": ("stride", "attack-tree"),
            "agent-security": ("stride", "attack-tree"),
        }
        methods: list[str] = []
        for skill in skills:
            methods.extend(m for m in table.get(skill, ("stride",)) if m not in methods)
        return tuple(methods)

    def resolve_packs_for_skills(self, skills: tuple[str, ...], *, pack_registry: Any = None) -> tuple[str, ...]:
        """Map agent skills to existing methodology packs. Packs stay methodology."""
        from emo_cyber_agent.agent_security.service import SKILL_PACK_MAP as _MAP

        selected: list[str] = []
        for skill in skills:
            for pack_id in _MAP.get(skill, ()):
                if pack_id not in selected:
                    selected.append(pack_id)
        if pack_registry is not None:
            known = set()
            try:
                known = {p.pack_id for p in pack_registry.list()}
            except Exception:
                known = set()
            selected = [p for p in selected if not known or p in known]
        return tuple(selected)

    def triggers_for_change(self, predicates_fired: dict[str, list[str]]) -> tuple[str, ...]:
        triggers: list[str] = []
        for predicate in sorted(predicates_fired):
            triggers.extend(t for t in CHANGE_TRIGGERS.get(predicate, ()) if t not in triggers)
        return tuple(triggers)

    def check_handoff(self, handoff: Any, *, current_snapshot_id: str) -> None:

        if current_snapshot_id != handoff.target_snapshot_id and current_snapshot_id not in handoff.compatible_snapshots:
            raise AgentSecurityError(AgentSecurityErrorCode.VERIFICATION_STALE, f"handoff {handoff.handoff_id} not compatible with snapshot {current_snapshot_id}")

    def build_evidence(self, assessment: AgentSecurityAssessment) -> list[Any]:
        from emo_cyber_agent.core.repository import redact_credentials
        from emo_cyber_agent.domain.models import EvidenceItem

        from emo_cyber_agent.agent_security.provenance import build_agent_provenance as _prov

        items: list[Any] = []
        for scenario in assessment.scenarios:
            summary = redact_credentials(f"agent threat hypothesis {scenario.category} subject={scenario.source} status={scenario.hypothesis_status}")[:400]
            items.append(EvidenceItem(
                source_tool="agent-security", source_version="1.0",
                target_asset_id=assessment.system.project_id or None,
                location=f"scenario:{scenario.scenario_id}", content_summary=summary,
                content_hash=__import__("emo_cyber_agent.threat_modeling.spec", fromlist=["canonical_digest"]).canonical_digest({"summary": summary}),
                provenance=_prov(audit_id=assessment.system.audit_id, project_id=assessment.system.project_id, snapshot_id=assessment.system.snapshot_id, subject_id=scenario.scenario_id, model_digest=assessment.digest, coverage=scenario.coverage),
            ))
        return items

    def report_view(self, assessment: AgentSecurityAssessment, evidence_ids: tuple[str, ...] = ()) -> dict[str, Any]:
        from emo_cyber_agent.threat_modeling.spec import assert_no_threat_verdicts as _assert
        import json as _json

        view = {
            "agent_system": {"agents": len(assessment.system.agents), "subagents": len(assessment.system.subagents), "mcp_servers": len(assessment.system.mcp_servers), "mcp_tools": len(assessment.system.mcp_tools)},
            "agent_attack_surface": {"completeness": assessment.surface.completeness, "elements": [e.model_dump(mode="json") for e in assessment.surface.elements]},
            "mcp_topology": dict(assessment.mcp_topology),
            "trust_boundaries": [b.model_dump(mode="json") for b in assessment.system.boundaries],
            "identity_delegation": {"identities": len(assessment.system.identities), "delegations": len(assessment.system.delegations)},
            "skills": sorted({s for a in assessment.system.agents for s in a.skill_ids}),
            "tools": sorted({t for a in assessment.system.agents for t in a.tool_ids}),
            "threat_scenarios": [s.model_dump(mode="json") for s in assessment.scenarios],
            "controls": [c.model_dump(mode="json") for c in assessment.controls],
            "evidence_references": list(evidence_ids),
            "coverage": assessment.surface.coverage,
            "limitations": list(assessment.limitations),
            "verification_handoffs": [h.model_dump(mode="json") for h in assessment.handoffs],
            "threat_model_delta": [],
            "framework_mappings": [s.framework_mappings for s in assessment.scenarios],
            "model_digest": assessment.digest,
            "kind": "threat-scenario-report",
        }
        _assert(_json.dumps(view))
        return view

    def load_official_templates(self, directory: Any) -> list[Any]:
        from pathlib import Path as _Path

        from emo_cyber_agent.agent_security.spec import AgentTemplateConfig as _Config

        try:
            import yaml as _yaml
        except ImportError as e:
            from emo_cyber_agent.agent_security.errors import AgentSecurityError as _E
            from emo_cyber_agent.agent_security.errors import AgentSecurityErrorCode as _C

            raise _E(_C.INVALID, "YAML parsing needs pyyaml") from e
        templates: list[Any] = []
        paths = sorted(_Path(directory).glob("*.yaml"))
        if not paths:
            from emo_cyber_agent.agent_security.errors import AgentSecurityError as _E2
            from emo_cyber_agent.agent_security.errors import AgentSecurityErrorCode as _C2

            raise _E2(_C2.INVALID, f"no agent templates in {directory}")
        for path in paths:
            try:
                doc = _yaml.safe_load(path.read_text())
            except Exception as e:
                from emo_cyber_agent.agent_security.errors import AgentSecurityError as _E3
                from emo_cyber_agent.agent_security.errors import AgentSecurityErrorCode as _C3

                raise _E3(_C3.INVALID, f"malformed template YAML: {e}") from e
            if not isinstance(doc, dict) or "agent_template" not in doc:
                from emo_cyber_agent.agent_security.errors import AgentSecurityError as _E4
                from emo_cyber_agent.agent_security.errors import AgentSecurityErrorCode as _C4

                raise _E4(_C4.INVALID, "template YAML must contain a top-level agent_template mapping")
            raw = doc["agent_template"]
            try:
                template = _Config(
                    template_id=str(raw.get("id", "")), name=str(raw.get("name", "")), version=str(raw.get("version", "")),
                    scope=tuple(raw.get("scope", ())), methods=tuple(raw.get("methods", ())),
                    declared_servers=tuple(raw.get("declared_servers", ())), provenance=dict(doc.get("provenance", {})),
                )
            except ValueError as e:
                from emo_cyber_agent.agent_security.errors import AgentSecurityError as _E5
                from emo_cyber_agent.agent_security.errors import AgentSecurityErrorCode as _C5

                raise _E5(_C5.INVALID, f"template invalid: {e}") from e
            templates.append(template)
        return templates
