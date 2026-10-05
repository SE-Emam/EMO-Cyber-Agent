# ECA-T014 — Universal CLI Interface

## Objective
Complete the CLI as an independent, CI-safe, scriptable fallback
interface — usable from terminals, CI/CD, pipes, cron, and agents without
MCP — over the SAME Core as the MCP adapter. CLI translates, Core
decides; findings never move exit codes; results go to stdout,
diagnostics to stderr.

## Scope
In scope: 7-command surface (doctor/audit/review/verify/status/report/
mcp), deterministic help, canonical `--format` modes, stdout/stderr
contract, 0–7 (+130) exit codes, expanded presence-only doctor, env/file
config layer (provider selection only, policy keys rejected), secret
handling (no secret flags/echoes), path/URL passthrough to Core scope,
signal handling, concurrency-by-statelessness, shell-safety (no command
construction), 24 offline tests, README documentation, packaging checks.
Out of scope (deferred): live audit persistence (status honestly reports
unknown-audit), full audit runner wiring, HTTP MCP, progress streaming.

## CLI Architecture
```text
CLI → Command Translator → Application/Core Service
→ Policy / Registry / Reasoning / Verification / Findings / Reporting
→ CLI Result Projection (stdout) + diagnostics (stderr)
```
`cli/main.py` holds translation + output + exit-code mapping only.
Purity-grep pinned: no adapter imports, no subprocess/shell, no
severity/classification/policy/evaluation constructs.

## Command Surface
Exactly: `doctor`, `audit <target>`, `review <target>`, `verify
--candidate --method --kind --locator --rationale --audit-id`,
`status <audit_id>`, `report --findings --audit-id --format`, `mcp`.
Surface-exactness test fails on any addition/removal. No command exists
without a real Core contract behind it.

## Help Contract
`--help` (global + per-command) is deterministic across runs, human-
readable, secret-free, and advertises only implemented options —
explicitly asserted absent: `--shell/--exec/--grant/--sudo/--allow-write/
--bypass-policy/--unsafe` and any secret-valued flags.

## Input Semantics
Targets pass through as validated values (Core owns scope/traversal
semantics from T005/T006/T010 — CLI adds no parallel path logic).
`verify` builds Core `FindingCandidate`/`VerificationRequest` via
pydantic (validation boundary) and returns the policy-gated PLAN
(same stance as MCP `cyber_verify`); input is never authorization.
`report` validates `SecurityFinding` items identically to the MCP path.

## Output Contract
`--format json` (audit/review/verify/status/doctor) emits machine-
readable sorted-key JSON; `report` reuses the three ECA-T012 formats
through the same `ReportService` (no second serializer). Human mode
prints verbatim Core words (CONFIRMED stays CONFIRMED; no "definitely
dangerous" rewrites). No CLI-specific schema exists anywhere.

## STDOUT/STDERR
Results → stdout; diagnostics/errors → stderr, enforced per command and
pinned by tests (JSON pipe-clean: `audit … --format json` parses after
ignoring stderr). `--output` writes results to a file, leaving stdout
empty.

## Exit Codes
0 SUCCESS · 1 AUDIT/DOMAIN FAILURE · 2 INVALID INPUT · 3 POLICY DENIED ·
4 SECURITY BLOCKED · 5 PROVIDER/TOOL UNAVAILABLE · 6 VERIFICATION
INCONCLUSIVE · 7 INTERNAL ERROR · 130 interrupted (POSIX standard, outside
the table). Core errors map deterministically (`_map_core_error`;
verification/report error codes covered); unknown exceptions → 7 with
type-name only, never traces. Findings presence never affects codes
(explicit test position: command status ≠ security results).

## doctor
Presence-only matrix: package/python/Core/5 schemas/tool-registry specs/
5 optional binaries (`AVAILABLE`/`UNAVAILABLE`)/GitHub+Supabase config
(`CONFIGURED`/`MISSING` from env names)/ MCP availability/provider config.
Values never printed (live-token test asserts absence); unreachability is
reported, never scored as a security failure.

## audit
`audit <target> [--mode quick|standard|deep] [--focus a,b] [--format]
[--output]` → Core `audit()` with forced `read_only`. Target echoed only
after output-side redaction (live-token test). Exit 0 on completion
regardless of findings.

## review
Same delegation shape via Core `review()`; uses the existing review
contract rather than inventing a CLI workflow.

## verify
Plan-only delegation to `VerificationService.plan()` (policy-gated,
scope-bound to the requested locator); cross-audit candidates → exit 3;
returns plan id/method/safety/capabilities. Execution stays per-audit
release integration (documented, consistent with MCP).

## status
Read-only by construction. Honest contract: no persisted audit store
exists in this phase, so any id returns structured `unknown-audit`
(exit 1) — never another audit's data, never invented state. The command
shape is frozen for the future store-backed implementation.

## report
Unchanged ECA-T012 path, now sharing exit-code/output helpers; cross-
audit findings → exit 3 via Core gate.

## mcp
Unchanged T013 wiring (`run_stdio()`); CLI only starts the adapter.

## Configuration
`load_config()`: explicit flags > `EMO_MODEL`/`EMO_PROVIDER_ENDPOINT` >
`~/.config/emo-cyber-agent/config.json` > defaults. Provider/model
endpoint selection ONLY — policy/capability/profile keys rejected at
load (test-pinned). Values never printed (presence only).

## Secret Handling
No secret-valued flags exist (unknown `--github-token` → exit 2 with
usage); env values never echoed (name-presence checks only); target
echoes redacted at serialization; trail-free commands keep no history.

## Path Safety
Targets forwarded untouched for Core scope enforcement (T005/T006
semantics reused, not reimplemented); traversal/absolute/null-byte cases
covered by Core validators downstream; CLI adds no parallel checks that
could disagree.

## Signal Handling
`_safe` boundary: `KeyboardInterrupt` → `interrupted` on stderr + exit
130; stateless commands hold nothing to corrupt. Subprocess test sends
SIGINT to a blocking `mcp` instance: exit ∈ {130, -SIGINT}, stderr
secret-free. Cancellation-through-lifecycle awaits a live runner (noted,
not faked).

## CI Behavior
Pipe-clean JSON (empty stderr on success), deterministic help, file
outputs, documented CI snippet in README. No TTY assumptions, no
interactive prompts anywhere (no `--yes` privilege path exists).

## Concurrency
Stateless commands: two `status` calls (or any pair) carry only their own
audit ids; isolation test asserts per-id echo with zero shared state
(no `current_audit` attribute exists by construction).

## Security Tests
In `test_cli.py` (offline): dangerous-flag rejection (5 variants),
shell-looking targets treated as data, secret-in-arg redaction (output +
stderr), secret-flag rejection, malformed/missing files, wrong/cross
audit, concurrent isolation, no-adapter-imports/no-logic source scan,
SIGINT behavior, oversized/unicode findings through report.

## Contract Tests
Per-command valid/invalid inputs, Core-error→exit mapping, structured
outputs (JSON parse + keys), doctor presence matrix (human + JSON),
surface-exactness, help determinism, exit-code constants, packaging entry
point.

## E2E Tests
`CLI → Core audit → Core-built finding (classify + promote) → CLI report
markdown` fully offline; finding id appears in rendered output —
proving the CLI is a live Core façade, not a mock. Plus CI-pipe test.

## Packaging
`pyproject.toml` entry point re-verified in-test; `--help` green via
`CliRunner`; subprocess invocation via `PYTHONPATH=src` (environment is
PEP-668-managed and package-uninstalled — documented limitation carried
from T013, no code hacks added for it).

## Documentation
README extended (§38): Installation, Quickstart, full command reference
with implemented-only options, formats + exit-code table, CI example,
security-model paragraph. No unimplemented capability documented.

## Files Inspected
- `cli/main.py` (skeleton + T012 report command), `mcp/*` (parity reference)
- `core/service.py`, `reporting.py`, `verification.py`, `policy.py`,
  `findings.py`, `correlation.py`
- `pyproject.toml`, `README.md`, `docs/16/02/03`, `docs/schemas/*`
- all prior unit tests

## Files Changed
- `src/emo_cyber_agent/cli/main.py` (REWRITTEN ~330 lines): codes,
  plumbing, config, 7 commands, signal boundary.
- `README.md` (ADDITIVE): install/quickstart/commands/exit-codes/CI/security.
- `tests/unit/test_cli.py` (NEW): 24 offline tests.
- (No Core/policy/adapter/schema changes; no new runtime deps.)

## Schemas
None added/changed (CLI reuses Core + report contracts verbatim).
6/6 schema files valid.

## Invariant Impact
1. Read-only — ENFORCED (forced profiles; verify is plan-only).
2. Untrusted content — ENFORCED (targets/args are data; redacted echoes).
3. No finding without evidence — PROTECTED (report gate reused).
4. No destructive action — ENFORCED (inexpressible in surface).
5. Tool outputs are evidence — PROTECTED (chain untouched).
6. Uncertainty explicit — PROTECTED (verbatim rendering).
7. Same contracts — ENFORCED (MCP≡CLI over identical Core calls).
8. Provider external — ENFORCED (config selects endpoint only).
9. Scanner provenance — PROTECTED (never exposed/needed).
10. No cross-project reuse — ENFORCED (per-command audit binding).
11. Specialist worker — ENFORCED (7 security commands; logic scan clean).
12. Host delegates — PROTECTED (CLI is the human/CI delegation face).
No invariant weakened; CLI adds zero authority (decision-verb scan is a test).

## Known Limitations
- `status` answers unknown-audit until audit persistence lands (honest,
  tested, documented — not papered over).
- `verify` returns plans; execution wiring is release integration.
- Package uninstallable-only-via-source here (PEP-668 system interpreter);
  validated through runner + subprocess seams instead.
- No progress streaming yet (commands are synchronous).

## Deferred Work
T015 Python API stabilization, T016 hardening/host-integration/RC;
persistent audit store + live runner wiring; progress/cancellation
streaming; MCP-over-HTTP (still deferred, never default).

## Evidence
- `pytest tests/ -p no:warnings` → `286 passed, 3 skipped`.
- `validate_schemas.py` → 6/6 OK. `compileall` → OK.
- Surface-exactness, help-determinism, pipe-clean JSON, exit-code,
  secret-absence, isolation, SIGINT, E2E, packaging tests all green.
- Files: `cli/main.py`, `README.md`, `tests/unit/test_cli.py`.

## Final Status
**PASS** — all 21 exit criteria met: frozen surface, Core-only
delegation, stdout/stderr split, JSON + report formats, deterministic
codes, presence-only doctor, source-installable invocation paths tested,
CI-safe, signal-correct, scope-safe, secret-free, adapter-free,
logic-free, isolated, security + contract + E2E tested, prior suites +
schemas green. No BLOCKED condition (no bypass, no direct adapter
access, no leakage, no shell, no cross-audit access, no
reinterpretation) observed. T015 (Python API) may proceed.
