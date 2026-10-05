"""Official security pack catalog — POST-RC-006.

YAML files under templates/skills/packs/ are the canonical authoring
artifacts. Loader parses, normalizes to the flat
security-skill-pack.schema.json shape, cross-validates, and registers
with loader-assigned TRUSTED provenance (never self-declared).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from emo_cyber_agent.skills.packs.errors import PackError, PackErrorCode
from emo_cyber_agent.skills.packs.pack import PackTrust, SecuritySkillPack
from emo_cyber_agent.skills.packs.validator import PackValidator


class PackRegistry:
    """Versioned pack discovery. No authority: grants nothing."""

    def __init__(self) -> None:
        self._packs: dict[tuple[str, str], SecuritySkillPack] = {}
        self._trust: dict[tuple[str, str], PackTrust] = {}

    def register(self, pack: SecuritySkillPack, *, trust: PackTrust = PackTrust.UNTRUSTED) -> None:
        key = (pack.pack_id, pack.version)
        if key in self._packs:
            raise PackError(PackErrorCode.DUPLICATE, f"duplicate pack: {pack.pack_id}@{pack.version}")
        self._packs[key] = pack
        self._trust[key] = trust

    def unregister(self, pack_id: str, version: str) -> None:
        key = (pack_id, version)
        if key not in self._packs:
            raise PackError(PackErrorCode.NOT_FOUND, f"pack not registered: {pack_id}@{version}")
        dependents = [f"{pid}@{ver}" for (pid, ver), pack in self._packs.items() if pack_id in pack.dependencies and (pid, ver) != key]
        if dependents:
            raise PackError(PackErrorCode.INVALID, f"pack depended on by: {sorted(dependents)}")
        del self._packs[key]
        del self._trust[key]

    def get(self, pack_id: str, version: str | None = None) -> SecuritySkillPack:
        if version is not None:
            try:
                return self._packs[(pack_id, version)]
            except KeyError:
                raise PackError(PackErrorCode.NOT_FOUND, f"pack not registered: {pack_id}@{version}") from None
        candidates = sorted(ver for (pid, ver) in self._packs if pid == pack_id)
        if not candidates:
            raise PackError(PackErrorCode.NOT_FOUND, f"pack not registered: {pack_id}")
        return self._packs[(pack_id, candidates[-1])]

    def list(self) -> list[SecuritySkillPack]:
        return [self._packs[key] for key in sorted(self._packs)]

    def versions(self, pack_id: str) -> list[str]:
        return sorted(ver for (pid, ver) in self._packs if pid == pack_id)

    def trust_of(self, pack_id: str, version: str) -> PackTrust:
        try:
            return self._trust[(pack_id, version)]
        except KeyError:
            raise PackError(PackErrorCode.NOT_FOUND, f"pack not registered: {pack_id}@{version}") from None

    def dependencies(self, pack_id: str, version: str | None = None) -> list[str]:
        return sorted(self.get(pack_id, version).dependencies)

    def check_cycles(self) -> list[str]:
        cycles: list[str] = []
        visited: dict[str, str] = {}

        def visit(node: str, stack: list[str]) -> None:
            visited[node] = "open"
            stack.append(node)
            try:
                deps = self.dependencies(node)
            except PackError:
                deps = []
            for dep in sorted(deps):
                if dep not in visited:
                    visit(dep, stack)
                elif visited[dep] == "open":
                    cycles.append("->".join([*stack[stack.index(dep):], dep]))
            stack.pop()
            visited[node] = "closed"

        for pid in sorted({pid for (pid, _v) in self._packs}):
            if pid not in visited:
                visit(pid, [])
        return sorted(cycles)

    def applicable(self, *, asset: str = "", domain: str = "") -> list[SecuritySkillPack]:
        result = []
        for pack in self.list():
            if asset and asset not in pack.applicable_assets:
                continue
            if domain and domain not in pack.security_domains:
                continue
            result.append(pack)
        return result


def build_known_capabilities(*, skill_registry: Any = None, tool_registry: Any = None) -> set[str]:
    """Allowlist a pack capability must belong to: Policy ∪ codeintel
    requests ∪ Task ∪ Playbook ∪ skill-declared capabilities."""
    known: set[str] = set()
    try:
        from emo_cyber_agent.core.policy import KNOWN_READ_CAPABILITIES

        known.update(KNOWN_READ_CAPABILITIES)
    except Exception:
        pass
    try:
        from emo_cyber_agent.code_intelligence.spec import PROVIDER_CAPABILITY_TO_REQUESTED

        known.update(PROVIDER_CAPABILITY_TO_REQUESTED.values())
    except Exception:
        pass
    try:
        from emo_cyber_agent.tasks.library import load_official_registry as _lt

        for task in _lt("templates/tasks/official").list():
            known.update(task.required_capabilities)
            known.update(task.denied_capabilities)
    except Exception:
        pass
    try:
        from emo_cyber_agent.playbooks.library import load_official_registry as _lp

        for playbook in _lp("templates/playbooks/official").list():
            known.update(playbook.requested_capabilities)
            known.update(playbook.denied_capabilities)
    except Exception:
        pass
    if skill_registry is not None:
        try:
            for skill in skill_registry.list():
                known.update(skill.required_capabilities)
        except Exception:
            pass
    return known


def _require_yaml() -> Any:
    try:
        import yaml as _yaml

        return _yaml
    except ImportError as e:
        raise PackError(PackErrorCode.INVALID, "YAML parsing needs pyyaml; use register(SecuritySkillPack) directly") from e


def load_yaml_text(text: str) -> dict[str, Any]:
    yaml = _require_yaml()
    try:
        doc = yaml.safe_load(text)
    except Exception as e:
        raise PackError(PackErrorCode.INVALID, f"malformed YAML: {e}") from e
    if not isinstance(doc, dict) or "pack" not in doc:
        raise PackError(PackErrorCode.INVALID, "YAML must contain a top-level pack mapping")
    return doc


def normalize_pack_dict(doc: dict[str, Any]) -> dict[str, Any]:
    p = doc.get("pack", {})
    ci = doc.get("code_intelligence", {})
    ev = doc.get("evidence", {})
    ver = doc.get("verification", {})
    sec = doc.get("security", {})
    return {
        "pack_id": p.get("id", ""),
        "name": p.get("name", ""),
        "version": p.get("version", ""),
        "purpose": p.get("purpose", ""),
        "skills": list(doc.get("skills", [])),
        "required_code_intelligence": list(ci.get("required", [])),
        "required_evidence": list(ev.get("required", [])),
        "required_verification": list(ver.get("methods", [])),
        "applicable_assets": list(doc.get("applicable_assets", [])),
        "security_domains": list(doc.get("security_domains", [])),
        "methodology": list(doc.get("methodology", [])),
        "checks": [
            {
                "check_id": c.get("id", ""),
                "title": c.get("title", ""),
                "methodology": list(c.get("methodology", [])),
                "evidence_required": list(c.get("evidence_required", [])),
                "evidence_sufficient": list(c.get("evidence_sufficient", [])),
                "evidence_missing": list(c.get("evidence_missing", [])),
                "verification_required": list(c.get("verification_required", [])),
                "verification_safety": str(c.get("verification_safety", "passive")),
                "high_risk": bool(c.get("high_risk", False)),
                "entry_level": str(c.get("entry_level", "HYPOTHESIS")),
                "codeintel_needs": list(c.get("codeintel_needs", [])),
                "source_kinds": list(c.get("source_kinds", [])),
                "sink_kinds": list(c.get("sink_kinds", [])),
                "hypothesis_template": str(c.get("hypothesis_template", "")),
            }
            for c in doc.get("checks", [])
        ],
        "stop_conditions": list(doc.get("stop_conditions", [])),
        "limitations": list(doc.get("limitations", [])),
        "required_capabilities": list(sec.get("requested", [])),
        "denied_capabilities": list(sec.get("denied", [])),
        "allowed_tools": list(doc.get("allowed_tools", [])),
        "dependencies": list(p.get("dependencies", [])),
        "provenance": dict(doc.get("provenance", {})),
    }


def validate_against_schema(flat: dict[str, Any], schema: dict[str, Any] | None = None) -> None:
    try:
        import jsonschema as _js
    except ImportError as e:
        raise PackError(PackErrorCode.INVALID, "schema cross-check needs jsonschema") from e
    if schema is None:
        import json as _json
        from pathlib import Path as _Path

        schema_path = _Path(__file__).resolve().parents[3] / "docs" / "schemas" / "security-skill-pack.schema.json"
        if schema_path.is_file():
            schema = _json.loads(schema_path.read_text())
        else:
            try:
                from emo_cyber_agent.core.resources import load_schema_text

                schema = _json.loads(load_schema_text("security-skill-pack"))
            except Exception as e:
                raise PackError(PackErrorCode.INVALID, f"pack schema unavailable: {e}") from e
    assert isinstance(schema, dict), "schema unavailable"
    try:
        _js.validate(flat, schema)
    except Exception as e:
        raise PackError(PackErrorCode.INVALID, f"schema validation failed: {e}") from e


def spec_from_yaml_text(text: str, *, check_schema: bool = True) -> SecuritySkillPack:
    flat = normalize_pack_dict(load_yaml_text(text))
    if check_schema:
        validate_against_schema(flat)
    try:
        return SecuritySkillPack(**flat)
    except ValueError as e:
        raise PackError(PackErrorCode.INVALID, f"SecuritySkillPack construction failed: {e}") from e


def load_official_packs(directory: str | Path, *, skill_registry: Any = None, tool_registry: Any = None) -> PackRegistry:
    directory = Path(directory)
    files = sorted(directory.glob("*.yaml"))
    if not files:
        raise PackError(PackErrorCode.NOT_FOUND, f"no official packs in {directory}")
    registry = PackRegistry()
    validator = PackValidator(skill_registry=skill_registry, tool_registry=tool_registry, known_capabilities=build_known_capabilities(skill_registry=skill_registry))
    for path in files:
        pack = spec_from_yaml_text(path.read_text())
        result = validator.validate(pack)
        if not result.valid:
            raise PackError(PackErrorCode.INVALID, f"official pack invalid {pack.pack_id}: {result.errors}")
        registry.register(pack, trust=PackTrust.TRUSTED)
    if registry.check_cycles():
        raise PackError(PackErrorCode.INVALID, f"official cycles: {registry.check_cycles()}")
    return registry
