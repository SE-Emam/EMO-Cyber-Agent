# EMO-Cyber-Agent — Security Baseline (ECA-T015)

Living document: attack surfaces, defenses, accepted limitations, residual
risks, and test inventory. Updated whenever a boundary changes. All claims
below are backed by tests in `tests/unit/test_hardening.py` unless marked
as residual (untestable offline).

## 1. Trust assumption

Everything outside Core is UNTRUSTED: repository content, README, source,
comments, commit messages, SQL, RLS expressions, scanner outputs, provider
responses, model outputs, MCP/CLI inputs, tool parameters, filenames, and
environment-derived values. No outer layer's goodwill is ever assumed.

## 2. Attack surface inventory

| # | Surface | Input | Trust | Authority | Side effects | Boundary | Defenses |
|---|---------|-------|-------|-----------|--------------|----------|----------|
| 1 | Core API (auditor/review/verify/doctor) | target strings, modes | untrusted | none (delegates) | none | input validation + redaction | shape checks, read_only forced |
| 2 | PolicyEngine (strict) | audit/tool/target/profile/caps | untrusted | ALLOW/DENY only | decision log | default-deny + version pin | 12+ unit tests, decision audit |
| 3 | ToolRegistry | ToolSpec dicts | untrusted | discovery only | registry map | duplicate/invalid rejection | registry tests |
| 4 | ToolExecutor | decision ids, targets | untrusted | none (port call) | subprocess | target+version-bound decisions, argv-only, confined cwd, allowlist env | execution tests |
| 5 | Repository adapters | identities, paths | untrusted | none | network/FS reads | scope, path/ref validation, redaction | scope + traversal tests |
| 6 | Supabase adapter | refs, SQL text | untrusted | none | network reads | scope, SQL classifier, redaction | SQL battery + scope tests |
| 7 | Scanner execution | targets, argv | untrusted | none | subprocess | strict policy + argv builders + output limits | toolchain tests |
| 8 | Evidence Store | evidence items | untrusted | none | memory map | audit-scoped reads, typed models | isolation tests |
| 9 | Correlation | store contents | untrusted-data | relations/candidates | memory only | deterministic rules, evidence-mandatory | correlation tests |
| 10 | Reasoning loop | provider responses | untrusted | none (proposes) | evidence via executor | validation, budgets, loop/progress detection | reasoning tests |
| 11 | Verification | requests, raw results | untrusted | status via criteria | evidence mint | safety levels, policy gate, budgets | verification tests |
| 12 | Finding lifecycle | candidates, suggestions | untrusted | gated transitions | finding records | lifecycle tables, eligibility, sandbox | findings tests |
| 13 | Reporting | finding objects | untrusted-data | none (projection) | strings | escaping, caps, redaction, reportability gate | reporting tests |
| 14 | MCP stdio | JSON-RPC lines | untrusted | none | stdout/stderr | shape+token screens, 1 MiB cap, statelessness | mcp tests + SDK interop |
| 15 | CLI | argv, files, env | untrusted | none | stdout/files | exit codes, no secret flags, config allow-list | cli tests |
| 16 | Configuration | file, env | untrusted | provider selection only | config map | key allow-list, precedence, no policy keys | config tests |
| 17 | Package install | pyproject, deps | pinned only | none | install | upper+lower pins, no URL deps | pin audit test |

## 3. Known defenses (all tested)

Default-deny policy with auditable decisions; target+version-bound
execution decisions; argv-only confined subprocesses with allowlist env;
scope-bound identities everywhere; credential redaction at construction,
serialization, errors, logs, and trail; untrusted envelopes preserved
end-to-end; evidence-mandatory constructors; deterministic lifecycles
with no shortcuts; audit-scoped stores/queries/contexts; bounded loops,
budgets, retries; canonical deterministic serialization with escaping.

## 4. Accepted limitations

- `content_hash` on evidence is claimant-provided, never re-verified (hash
  mismatch changes grouping, never grants trust).
- Tool `version` strings are opaque provenance labels ("latest" is never
  resolved, only recorded).
- `DefaultPolicyEngine` allow-all remains for the ECA-T005/T006 read
  paths; the execution path is strict-only by constructor type-check.
- Real version discovery, cgroups, persistent audit store, live runners,
  and remote transports are release-integration work, not present here.

## 5. Residual risks (cannot be proven offline — stated, not hidden)

- External provider availability and real GitHub/Supabase permission
  semantics differ from doubles by definition.
- Real MCP host behavior beyond the reference SDK subset.
- Platform-specific process isolation (Windows drive semantics guarded by
  denial; POSIX assumed elsewhere).
- Dependency vulnerabilitiespost-audit-date (pins recorded; no live DB).
- Model-provider data handling once a real reasoner is wired (interface
  exists; no implementation ships).

## 6. Test inventory

`test_hardening.py` (37 tests): policy-bypass ×4, registry poisoning ×3,
execution boundary ×2, network ×3, filesystem ×2, secrets ×1, injection
corpus ×2, evidence poisoning ×2, stale/replay ×3, reasoner ×1,
verification ×1, finding ×2, reporting ×1, MCP ×2, CLI ×1, config ×1,
dependencies ×1, races ×3, resources ×4, fuzz ×3, invariant matrix ×1.
Plus 286 pre-existing unit/contract/security tests across 9 modules.
Skipped: 3 optional real-binary probes (absent tools only).

## 7. How to run the gate

```bash
python3 -m pytest tests/ -p no:warnings -q
python3 scripts/validate_schemas.py
```

No external credentials needed. Any failure blocks release; see the
assessment report for the per-invariant matrix.
