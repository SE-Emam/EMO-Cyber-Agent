"""Skill registry — POST-RC-001.

Discovery + contracts + validation. Never grants capabilities, never
executes methodology, never overrides policy. Every registration runs the
full validation pipeline; content stays untrusted until proven otherwise.
"""

from __future__ import annotations

from emo_cyber_agent.skills.spec import (
    SkillSpec,
    SkillTrust,
    SkillValidation,
    high_risk_capabilities,
    scan_injection_phrases,
)


class SkillRegistry:
    """Version-aware skill store with dependency validation."""

    def __init__(self) -> None:
        self._skills: dict[tuple[str, str], SkillSpec] = {}
        self._validations: dict[tuple[str, str], SkillValidation] = {}

    # -- registration --
    def register(self, spec: SkillSpec) -> SkillValidation:
        key = (spec.skill_id, spec.version)
        if key in self._skills:
            raise ValueError(f"skill already registered: {spec.skill_id}@{spec.version}")
        validation = self.validate(spec)
        if not validation.valid:
            raise ValueError(f"invalid skill {spec.skill_id}@{spec.version}: {validation.errors}")
        self._skills[key] = spec
        self._validations[key] = validation
        return validation

    def unregister(self, skill_id: str, version: str) -> None:
        key = (skill_id, version)
        if key not in self._skills:
            raise ValueError(f"skill not registered: {skill_id}@{version}")
        # refuse removal while others depend on it (explicit, auditable)
        dependents = [f"{sid}@{ver}" for (sid, ver), spec in self._skills.items() if skill_id in spec.dependencies and (sid, ver) != key]
        if dependents:
            raise ValueError(f"skill in use by: {sorted(dependents)}")
        del self._skills[key]
        del self._validations[key]

    # -- validation pipeline --
    def validate(self, spec: SkillSpec) -> SkillValidation:
        errors: list[str] = []
        warnings: list[str] = []
        # dependency validation (missing + self-dependency; cycles checked across registry on resolve)
        for dep in spec.dependencies:
            if dep == spec.skill_id:
                errors.append("self-dependency")
            elif not any(sid == dep for (sid, _ver) in self._skills):
                errors.append(f"missing-dependency:{dep}")
        # capability analysis (request-only; high-risk requests mark untrusted)
        risky = high_risk_capabilities(spec.required_capabilities)
        if risky:
            warnings.append(f"high-risk-capabilities:{','.join(sorted(risky))}")
        # injection check over all free-text methodology content
        hits = scan_injection_phrases(spec.description, *spec.methodology, *spec.objectives, *spec.security_constraints)
        if hits:
            warnings.append(f"injection-patterns:{','.join(hits)}")
        trust = SkillTrust.UNTRUSTED if warnings else SkillTrust.TRUSTED
        return SkillValidation(skill_id=spec.skill_id, version=spec.version, valid=not errors, trust=trust, errors=tuple(errors), warnings=tuple(warnings))

    # -- discovery --
    def get(self, skill_id: str, version: str | None = None) -> SkillSpec:
        if version is not None:
            try:
                return self._skills[(skill_id, version)]
            except KeyError:
                raise ValueError(f"skill not registered: {skill_id}@{version}") from None
        candidates = sorted((ver for (sid, ver) in self._skills if sid == skill_id), reverse=True)
        if not candidates:
            raise ValueError(f"skill not registered: {skill_id}")
        return self._skills[(skill_id, candidates[0])]

    def list(self) -> list[SkillSpec]:
        return [self._skills[key] for key in sorted(self._skills)]

    def versions(self, skill_id: str) -> list[str]:
        return sorted(ver for (sid, ver) in self._skills if sid == skill_id)

    def validation_of(self, skill_id: str, version: str) -> SkillValidation:
        return self._validations[(skill_id, version)]

    def dependencies(self, skill_id: str, version: str | None = None) -> list[str]:
        return list(self.get(skill_id, version).dependencies)

    def compatible_skills(self, skill_id: str, version: str | None = None) -> list[SkillSpec]:
        """Skills sharing domain or linked by dependency, same registry only."""
        base = self.get(skill_id, version)
        out = []
        for spec in self.list():
            if spec.skill_id == base.skill_id:
                continue
            if spec.domain == base.domain or base.skill_id in spec.dependencies or spec.skill_id in base.dependencies:
                out.append(spec)
        return out

    def check_cycles(self) -> list[str]:
        """Return dependency cycles (empty = acyclic). Deterministic order."""
        cycles: list[str] = []
        visited: dict[str, str] = {}

        def visit(node: str, stack: list[str]) -> None:
            visited[node] = "open"
            stack.append(node)
            try:
                deps = self.dependencies(node)
            except ValueError:
                deps = []
            for dep in sorted(deps):
                if dep not in visited:
                    visit(dep, stack)
                elif visited[dep] == "open":
                    cycles.append("->".join([*stack[stack.index(dep):], dep]))
            stack.pop()
            visited[node] = "closed"

        for sid in sorted({sid for (sid, _v) in self._skills}):
            if sid not in visited:
                visit(sid, [])
        return sorted(cycles)
