# ECA-T015 — Security Assessment (Hardening & Adversarial Evaluation)

## Threat Model
Adversary controls every input Core ever sees: repository text, scanner
output, provider responses, model outputs, MCP/CLI parameters, filenames,
environment values, and config files. Goal: bypass policy, execute
arbitrary commands, cross audit/project boundaries, leak secrets, forge
evidence/findings, or promote attacker text to instruction/authority.
Core is the only trusted component; every boundary was attacked in-test.

## Attack Surface
17 surfaces inventoried with input/trust/authority/effects/boundary/
defenses each — see `reports/security/00-security-baseline.md` §2
(Core API, PolicyEngine, ToolRegistry, ToolExecutor, repository adapters,
Supabase adapter, scanner execution, Evidence Store, correlation,
reasoning, verification, finding lifecycle, reporting, MCP, CLI,
configuration, package installation).

## Test Coverage
37 new adversarial tests + 286 pre-existing unit/contract/security tests
= **323 passed, 3 skipped** (skips: optional real-binary probes only).
Fuzz: 3 seeded campaigns (targets ×500, capabilities ×200, MCP ×100,
CLI ×60, projections ×60). Races: evidence/store/report/policy
concurrency. Resources: 5 MiB file, 500 findings, 300-evidence graph, all
bounded <10s.

## Policy Attacks
Forged/unknown caps, metadata escalation, cross-project reuse, malformed
profiles, stale-version + retargeted decisions → all DENY. Two REAL gaps
found and fixed in-boundary: (1) decisions were not target-bound
(replay across targets in one audit) and ignored policy versions —
`ToolExecutor` now enforces both; (2) pre-existing tests updated to the
stricter contract.

## Tool Attacks
Poisoned specs (extra caps, fake versions, impersonating ids) register
as inert discovery at most; use denied; duplicates rejected; mid-flow
registry mutation cannot swap the resolved spec (version-pinned
invocation asserts it).

## Execution Attacks
Shell/argument/option injection, traversal/absolute/symlink/null-byte
escapes, malicious cwd, poisoned/secret env, oversized streams, timeout
abuse, substitution syntax — all contained by argv-only confined
execution; no `shell=True`, no raw commands anywhere in Core/adapters.

## Injection Tests
12-phrase corpus × (README, evidence, MCP/CLI params, tool output, SQL
comments, finding text): zero candidates, zero authority changes, zero
leaks. Tool-output injection stays inside untrusted envelopes end to end.

## Isolation Tests
Cross-audit (evidence/verification/finding/cache/decision/context) and
cross-project (repo↔supabase↔scanner artifacts) matrices all deny;
correlation never joins across audits (split-facts test); contexts filter
by audit; fingerprints are audit-bound.

## Secrets
Planted tokens/keys/passwords across CLI/MCP params, repo content,
scanner output, provider errors, model responses, titles, summaries,
reports, logs: absent from invocations, evidence-converted outputs,
reports, stdout, stderr, and trails. Prevention is structural (references
not values, allowlist env, constructor refusal); regex redaction is the
second gate, never the only one.

## MCP
Malformed/oversized/unknown/nested-abuse messages → defined codes only;
capability/policy/shell injection → INVALID_PARAMS; cross-audit →
PERMISSION_DENIED; concurrent confusion → isolated; protocol-level
injection → data. Adapter holds no decisions (source-scanned in-test).

## CLI
Option/shell/path injection, secret args (redacted echoes), malformed
files, stdout/stderr split, wrong/cross audits, bypass flags, SIGINT
(130, secret-free), concurrent isolation, symlink/typed config attacks,
unknown-env exclusion. No adapter imports or logic in CLI (scanned).

## Dependencies
All runtime deps carry lower+upper pins, no URL/git sources (parsed from
pyproject in-test); installed inventory recorded (pydantic/typer/rich
families). No new dependency added for this phase.

## Fuzzing
Seeded deterministic campaigns (fixed seed `0xECA7`, reproducible):
target parsing (shape vs confinement properties separated), capability
strings (unknown never allowed), MCP wire (only defined codes),
CLI targets (only known exits, no traces/secrets), projections (invalid
rejected pre-report, valid preserved). Two campaign findings FIXED:
null-byte paths and `%`-encoded traversal (see below).

## Resource Exhaustion
5 MiB file → 500-char preview cap with digest intact; 500 findings →
correct summary <10s; 300-evidence graph → completes <10s; reasoner
summaries capped at construction; JSONL newline-collapse hardened so
single-line contexts stay single-line (found by the campaign, fixed).

## Race Tests
10×20 concurrent evidence inserts: exact 200, correct per-audit split,
zero errors; 8 concurrent reports byte-identical modulo timestamp;
20 concurrent decisions: 20 unique ids. No state bleeding (GIL-atomic
structures + no shared mutable audit state by design).

## Invariant Matrix
All 12 invariants carry live regression assertions in
`test_invariant_regression_matrix` (read-only deny, untrusted envelope,
evidenceless denial, destructive deny, data-not-instruction,
graph-grounded confidence, MCP≡CLI Core path, no model SDK, 4-scanner
registry, audit isolation, specialist surface, delegation-shaped report).

## Known Vulnerabilities
Two REAL boundary weaknesses found BY this campaign and fixed IN the
boundary (not masked): (1) unbound execution decisions (target+version —
fixed in `ToolExecutor` + regression tests); (2) null-byte and
percent/double-encoded traversal accepted by path/ref validators +
newline smuggling in single-line report contexts (fixed in validators +
`md_escape`). A third test-authoring conflation (confinement vs shape
validation) was corrected in tests, not code. No BLOCKED condition
remains: no bypass, no arbitrary execution, no leakage, no model
authority, no lifecycle skip, no unsafe default anywhere in the suite.

## Residual Risks
Per baseline §5 (external provider semantics, live-host behavior,
platform specifics, post-audit dependency CVEs, future model-provider
handling, unwired harnesses/runners/stores, claimant-provided hashes and
version strings). Stated explicitly; nothing graded PASS without a test.

## Accepted Limitations
Per baseline §4 (hash/version claimant data, allow-all legacy read path
with strict-only execution gate, deferred harnesses/runners/transports/
caching/scoring). No feature was added to pass a test; two existing
behaviors were tightened, one test corrected.

## Security Evidence
- `tests/unit/test_hardening.py`: 37/37 green.
- Full suite: 323 passed, 3 skipped. Schemas 6/6. Compile clean.
- Fuzz seeds fixed; race/resource bounds asserted with timings.
- Files changed: `core/execution.py` (+target/version binding),
  `core/repository.py` (null-byte + encoded-traversal + drive-letter
  denial), `core/reporting.py` (newline collapse), `tests/unit/
  test_toolchain.py` (stricter contracts), `tests/unit/test_hardening.py`
  (NEW), `reports/security/*` (NEW ×2).
- Command gate: `python3 -m pytest tests/ -p no:warnings -q` (+
  `scripts/validate_schemas.py`), credential-free, offline.

## Final Status
**PASS** — all 27 exit criteria met: baseline documented, inventory
complete, 12/12 invariant regressions green, every attack family above
tested with DENY/contain outcomes, real findings fixed in-boundary with
regression tests, no masking workarounds, residual risks written plainly,
full suite green. ECA-T016 (Release Candidate) may proceed.
