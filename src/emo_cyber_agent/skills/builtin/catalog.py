"""Built-in official skills — POST-RC-001.

Each entry is a methodology declaration (phases, checks, evidence rules),
not a prompt. All request read-only capabilities only; Core Policy decides.
"""

from __future__ import annotations

from emo_cyber_agent.skills.registry import SkillRegistry
from emo_cyber_agent.skills.spec import SkillSpec

_READ = ("repository.read",)
_LIST = ("repository.list",)
_SEARCH = ("repository.search",)
_META = ("repository.metadata",)
_DB = ("supabase.table.read",)
_RLS = ("supabase.policy.read",)
_GRANT = ("supabase.grant.read",)
_SCAN = ("scanner.local.execute",)
_EVIDENCE = ("file-evidence", "tool-evidence")
_STOP = ("scope-exhausted", "budget-exhausted", "no-progress")


def _skill(skill_id: str, name: str, domain: str, description: str, *, triggers=(), objectives=(), inputs=(), caps=_READ, tools=("repository.read",), methodology=(), evidence=_EVIDENCE, verification="passive confirmation via evidence re-observation", deps=(), constraints=("read-only", "no-write", "untrusted-content")) -> SkillSpec:
    return SkillSpec(
        skill_id=skill_id,
        name=name,
        version="1.0.0",
        description=description,
        domain=domain,
        triggers=tuple(triggers),
        objectives=tuple(objectives),
        inputs=tuple(inputs),
        required_capabilities=tuple(caps),
        allowed_tools=tuple(tools),
        methodology=tuple(methodology) or ("inventory targets", "collect read-only facts", "record evidence with provenance", "stop on scope exhaustion"),
        evidence_requirements=tuple(evidence),
        verification_strategy=verification,
        stop_conditions=tuple(_STOP),
        output_contract="SecurityObservation list with evidence references",
        dependencies=tuple(deps),
        security_constraints=tuple(constraints),
        provenance={"source": "builtin", "spec_version": "1.0"},
        tests=(f"tests[{skill_id}]",),
    )


BUILTIN_SKILLS: list[SkillSpec] = [
    _skill("authentication", "Authentication Review", "authentication", "Review login, session, token, MFA, and password flows for design flaws.", triggers=("auth", "jwt", "oauth"), objectives=("map auth boundaries", "list auth assumptions"), inputs=("source tree",), caps=(*_READ, *_LIST), tools=("repository.read", "repository.list"), methodology=("enumerate auth entrypoints", "trace session/token lifecycle", "record assumptions as evidence"), deps=()),
    _skill("authorization", "Authorization Review", "authorization", "Review access-control decisions, ownership checks, and privilege boundaries.", triggers=("auth", "supabase"), objectives=("map authorization checks", "flag missing checks"), inputs=("source tree", "schema facts"), caps=(*_READ, *_DB, *_RLS), tools=("repository.read", "supabase.policy.read"), methodology=("locate trust boundaries", "trace identifier to data access", "compare against policy facts"), deps=("authentication",)),
    _skill("api-security", "API Security Review", "api", "Review endpoints for auth, input handling, rate limits, and exposure.", triggers=("package.json", "auth", "jwt"), objectives=("inventory endpoints", "check auth coverage"), inputs=("routes",), caps=(*_READ, *_SEARCH), tools=("repository.read", "repository.search"), deps=("authentication", "authorization")),
    _skill("injection", "Injection Analysis", "injection", "Trace untrusted input to sinks: SQL, command, template, LDAP, XPath.", triggers=(".py",), objectives=("find source-sink paths",), inputs=("source tree",), caps=(*_READ, *_SEARCH), tools=("repository.search", "repository.read"), deps=()),
    _skill("secrets", "Secret Exposure Review", "secrets", "Detect secret indicators in tracked files without collecting values.", triggers=(".env", "gitleaks"), objectives=("list secret indicators with digests",), inputs=("tracked files",), caps=(*_READ, *_LIST), tools=("repository.read", "scanner.local.execute"), evidence=("fingerprint-evidence",)),
    _skill("dependency-security", "Dependency Security", "dependency", "Inventory dependencies and match against vulnerability metadata.", triggers=("package.json", "requirements.txt", "pyproject.toml"), objectives=("list packages", "record known vulns"), inputs=("manifests",), caps=(*_READ, *_LIST), tools=("repository.read", "scanner.local.execute"), deps=()),
    _skill("supply-chain", "Supply-Chain Review", "supply-chain", "Review lockfiles, registries, CI provenance, and update hygiene.", triggers=("package-lock.json", "requirements.txt"), objectives=("verify lockfile presence", "record sources"), inputs=("manifests", "CI config"), caps=(*_READ, *_LIST), tools=("repository.read",), deps=("dependency-security",)),
    _skill("configuration", "Configuration Review", "configuration", "Review defaults, debug flags, CORS, TLS, and secret handling in config.", triggers=(".env", "Dockerfile", "pyproject.toml"), objectives=("list insecure defaults",), inputs=("config files",), caps=(*_READ,), tools=("repository.read",)),
    _skill("database-security", "Database Security", "database", "Review schema exposure, privileges, and dangerous defaults.", triggers=("supabase", "schema.sql", "migration"), objectives=("inventory objects", "record grants"), inputs=("schema facts",), caps=(*_DB, *_GRANT), tools=("supabase.table.read", "supabase.grant.read")),
    _skill("supabase", "Supabase Review", "supabase", "Project-scoped Supabase metadata collection: schema, auth, storage.", triggers=("supabase",), objectives=("collect project facts",), inputs=("project ref",), caps=(*_DB, *_META), tools=("supabase.table.read", "supabase.project.read"), deps=("database-security",)),
    _skill("rls", "Row-Level Security Review", "rls", "Record RLS enablement, policies, and grants as separate facts.", triggers=("supabase", "schema.sql"), objectives=("rls-enabled state", "policy list", "grant list"), inputs=("schema facts",), caps=(*_RLS, *_GRANT, *_DB), tools=("supabase.policy.read", "supabase.grant.read"), deps=("supabase", "database-security")),
    _skill("business-logic", "Business-Logic Review", "business-logic", "Find valid-operations-combined-wrongly flaws: bypass, replay, races.", triggers=(".py", "payment", "workflow"), objectives=("map workflows", "list state transitions"), inputs=("source tree",), caps=(*_READ,), tools=("repository.read",)),
    _skill("race-conditions", "Race Condition Review", "concurrency", "Review TOCTOU, check-then-act, and idempotency gaps visible statically.", triggers=("payment", "workflow"), objectives=("list shared-state writes",), inputs=("source tree",), caps=(*_READ,), tools=("repository.read",), deps=("business-logic",)),
    _skill("cryptography", "Cryptography Review", "cryptography", "Check algorithm choice, randomness, key handling, and JWT validation.", triggers=("cipher", "jwt"), objectives=("list crypto primitives",), inputs=("source tree",), caps=(*_READ, *_SEARCH), tools=("repository.search",)),
    _skill("data-exposure", "Data Exposure Review", "data-exposure", "Find over-exposed fields, logs, errors, and storage policies.", triggers=("s3", "bucket"), objectives=("list exposure points",), inputs=("source tree", "schema facts"), caps=(*_READ, *_DB), tools=("repository.read",)),
    _skill("cloud-security", "Cloud Security Review", "cloud", "Review IAM, storage, network exposure, and secrets in cloud config.", triggers=(".tf", "s3"), objectives=("list cloud resources",), inputs=("iac files",), caps=(*_READ,), tools=("repository.read"), deps=("configuration",)),
    _skill("container-security", "Container Security Review", "container", "Review base images, users, secrets, and runtime flags.", triggers=("Dockerfile", "docker-compose"), objectives=("list image/user/secret facts",), inputs=("container files",), caps=(*_READ,), tools=("repository.read",), deps=("configuration",)),
    _skill("infrastructure-as-code", "IaC Security Review", "iac", "Review Terraform and IaC for open ingress, encryption, and drift.", triggers=(".tf",), objectives=("list misconfigurations",), inputs=("iac files",), caps=(*_READ,), tools=("repository.read",), deps=("cloud-security",)),
    _skill("frontend-security", "Frontend Security Review", "frontend", "Review XSS sinks, sinks-to-DOM flows, CSP, and client trust.", triggers=("package.json", ".tsx", ".ts", "next.config"), objectives=("list sinks",), inputs=("frontend tree",), caps=(*_READ, *_SEARCH), tools=("repository.search",)),
    _skill("backend-security", "Backend Security Review", "backend", "Review handlers, middleware ordering, and server trust boundaries.", triggers=(".py", ".ts", "tsconfig.json", "next.config"), objectives=("list handlers",), inputs=("backend tree",), caps=(*_READ,), tools=("repository.read"), deps=("api-security",)),
    _skill("ai-security", "AI Application Security", "ai", "Review prompt handling, output trust, RAG boundaries, and tool use.", triggers=("prompt", "agent"), objectives=("list AI trust boundaries",), inputs=("source tree",), caps=(*_READ,), tools=("repository.read",)),
    _skill("agent-security", "Agent Security Review", "agent", "Review agent planning, tool delegation, memory, and agency limits.", triggers=("agent", "mcp"), objectives=("list agency boundaries",), inputs=("agent config",), caps=(*_READ,), tools=("repository.read",), deps=("ai-security",)),
    _skill("mcp-security", "MCP Server Security Review", "mcp", "Review MCP tool surface, scopes, descriptions, and token handling.", triggers=("mcp",), objectives=("list tools and scopes",), inputs=("mcp config",), caps=(*_READ,), tools=("repository.read",), deps=("agent-security",)),
    _skill("threat-modeling", "Threat Modeling", "threat-model", "Enumerate assets, trust boundaries, dataflows, and threats.", triggers=("threat",), objectives=("asset inventory", "boundary map"), inputs=("architecture docs",), caps=(*_READ, *_LIST), tools=("repository.read", "repository.list")),
    _skill("code-review-security", "Security Code Review", "review", "General secure-review pass producing observations with evidence.", triggers=("review",), objectives=("list observations",), inputs=("diff or tree",), caps=(*_READ,), tools=("repository.read",)),
]

BUILTIN_INDEX: dict[str, SkillSpec] = {s.skill_id: s for s in BUILTIN_SKILLS}


def load_builtin_registry() -> SkillRegistry:
    """Build a registry preloaded with all builtin skills (validated)."""
    from emo_cyber_agent.skills.registry import SkillRegistry

    registry = SkillRegistry()
    for spec in BUILTIN_SKILLS:
        registry.register(spec)
    cycles = registry.check_cycles()
    if cycles:
        raise ValueError(f"builtin dependency cycles: {cycles}")
    return registry
