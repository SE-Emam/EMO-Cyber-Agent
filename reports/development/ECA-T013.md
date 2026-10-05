# ECA-T013 — MCP Server Adapter

## Objective
Expose EMO-Cyber-Agent to any MCP host (OpenCode, Hermes, pi, Cline,
VS Code, Forge, Klio, future hosts) as a security-specialist sub-agent
through 5 high-level tools. MCP is an ADAPTER ONLY: translate → validate
interface shape → delegate to Core → serialize. Core remains the single
source of truth; no second agent, policy, reporting, or finding engine
exists in this layer.

## Scope
In scope: stdio JSON-RPC lifecycle, 5 tools with strict input schemas,
Core delegation (audit/review/verify-plan/report/status), error mapping,
per-request audit scoping, concurrency-by-construction, sanitized stderr
logs, `cyber-agent mcp` wiring, 24 offline tests, real-SDK interop proof.
Out of scope (deferred): HTTP transport (abstraction noted, not built,
never default), MCP prompts/resources, auth beyond stdio process
boundary, full MCP feature surface.

## Architecture
```text
MCP Client → MCP Adapter → Core Application Service
→ Policy / Registry / Reasoning / Verification / Reporting
→ Result → MCP serialization
```
`mcp/protocol.py` frames bytes; `mcp/tools.py` declares surface;
`mcp/delegate.py` translates; `mcp/server.py` dispatches stdio.
Forbidden and absent by test: MCP→policy/tool/finding/severity/
verification/GitHub/Supabase/shell decisions or calls.

## MCP Tool Surface
Exactly: `cyber_audit`, `cyber_review`, `cyber_verify`, `cyber_report`,
`cyber_status`. No registry/scanner/repository/database internals leak
(test scans the discovery payload). Descriptions state the read-only
contract; write/delete/execute-arbitrary language is absent (pinned).

## Tool Contracts
- `cyber_audit{target, mode?, focus?, audit_id?}` → Core `audit()` (read_only forced).
- `cyber_review{target, focus?, audit_id?}` → Core `review()`.
- `cyber_verify{audit_id, candidate, method, target{kind,locator}, rationale, statement?}` → candidate/request built via Core models (validation boundary) → `VerificationService.plan()` (policy-gated) → returns the PLAN (`planned`); input is never authorization, execution wiring stays per-audit release integration.
- `cyber_report{audit_id, findings[], format, include_non_reportable?}` → Core `ReportService` (existing ECA-T012 path, serializers reused verbatim).
- `cyber_status{audit_id?}` → Core `doctor()` + high-level capability list. Read-only; no secrets, no other audits, no internals, no state mutation.

## Input Schemas
Per-tool JSON-Schema-shaped dicts enforced by a dependency-free shape
validator (required/types/enums/lengths/array caps/closed objects) PLUS a
token-based forbidden-key screen (permission/capability/policy/command/
shell/credentials/model/role/admin/…). Token (not substring) matching so
legitimate keys like `description` or `regression_key` never false-positive
(both cases test-pinned). Violations → INVALID_PARAMS, never repaired
into actions. `controlled_reproduction` is deliberately absent from verify
methods (read-only phase).

## Output Schemas
Success: `{status:"ok", tool, audit_id, result:{…}, references:{…}}`
serialized with sorted keys. Domain failures ride as
`{content:[{type:"text",text:"{status:error,tool,audit_id,code,message}"}],
isError:true}` — hosts can parse errors as data, never as crashes.

## Error Mapping
INVALID_REQUEST→INVALID_PARAMS(-32602); POLICY_DENIED/OUT_OF_SCOPE→
PERMISSION_DENIED; NOT_FOUND→NOT_FOUND; TIMEOUT→TIMEOUT;
SERVICE_UNAVAILABLE→SERVICE_UNAVAILABLE; SECURITY_BLOCKED→
SECURITY_BLOCKED; else INTERNAL_ERROR. Protocol violations use JSON-RPC
codes (-32700/-32600/-32601/-32602). No traces, no secrets (redacted at
construction and at every serialization point, including echoed targets).

## Session Identity
`audit_id` (+candidate-bound audit for verify) travels per request;
handlers build fresh Core services per call; the server object holds zero
audit state (attribute-absence test). Connection ≠ identity; interleaved
audits on shared/dedicated instances stay isolated (tested both ways).

## Concurrency
Statelessness is the mechanism: no globals, no current-audit, no caches.
Two clients × two audits interleave with distinct audit ids and targets.

## Progress
Core owns state; this phase returns synchronous results plus audit/session
ids. Progress notifications and cancellation paths are deferred to host
integration (documented, not faked): no invented queue system.

## Cancellation
Deferred with progress (same rationale). Domain lifecycles already gate
transitions; MCP adds no parallel state machine that could disagree.

## stdio Transport
`cyber-agent mcp` runs `run_stdio()`: line-delimited JSON-RPC on
stdin/stdout, logs on stderr only, blank lines skipped, 1 MiB line cap,
EOF → clean exit 0, unexpected exceptions → -32603 without leaking
internals, protocol stays alive. Verified end-to-end over a real
subprocess (4 messages incl. a notification → exactly 4 responses).

## HTTP Decision
Deferred/optional by design: no remote server built, never default, no
implicit trust assumptions recorded for any future mode (explicit
auth contract required first). A `MCPTransportPort` abstraction is
unnecessary while stdio is the only transport — not invented.

## Authentication Boundary
stdio local mode relies on the host process/user boundary (§20 posture,
documented). No fake in-protocol auth added. No auth headers, tokens, or
credentials are accepted, logged, or echoed anywhere in this layer.

## Secret Handling
Redaction at input validation errors, Core-result echo points, error
mapping, and stderr logs (dual redactors). Tests plant live-looking
tokens in targets and error paths and assert absence in responses AND
captured logs. Status surface grepped clean of secret-adjacent words AND
internal tool names.

## Untrusted Content
Repository/SQL/scanner/finding text crosses responses as escaped DATA:
report path reuses Core escaping; link/JS/script constructs neutralized
(entity-escaped, inert); oversized findings denied by count cap (never
silently truncated) with a second 1 MiB output gate behind it.

## Host Delegation
Host: "audit this project for auth/RLS issues" → EMO investigates
internally → structured, auditable result. Hosts learn nothing of
Semgrep/Trivy/GitHub/Supabase internals (discovery-payload scan proves
it). Specialist boundary held: no write_code/refactor/generate_app/
edit_file surface exists.

## Specialist Boundary
Covered above; additionally the adapter cannot reach any general-coding
capability because none exists in Core's exposed contracts.

## Packaging
`pyproject.toml` already declares `cyber-agent = emo_cyber_agent.cli.main:app`
(verified in-test); `mcp` command now runs the real server instead of the
Phase-11 stub (exit-3 placeholder removed). Environment note: the system
interpreter here is PEP-668-managed and the package is not pip-installed,
so tests drive the CLI via `CliRunner` and stdio via `sys.executable +
PYTHONPATH=src` subprocess — no development hacks inside the shipped
code paths. Zero new runtime dependencies added (stdlib + existing
pydantic/typer only).

## Host Compatibility
Proven two ways: (1) in-repo `MockMcpClient` fixture driving the full
initialize→list→call sequences for audit/status/report/verify; (2) LIVE
interop with the reference `mcp` SDK (venv install, kept out of runtime
deps): SDK `ClientSession` over real stdio completed initialize
(protocol 2025-06-18), `list_tools` (exact 5 names), `call_tool`
cyber_status + cyber_audit — `INTEROP PASS`. Any host speaking the same
lifecycle subset interoperates identically.

## Security Tests
In `test_mcp.py` (offline): invalid/unknown/missing-field inputs,
capability+permission+policy+model+role injection keys, shell/command/
script params, traversal/absolute/external/`*` targets, cross-audit
candidate, credential-in-input (response + logs), malicious finding
content, oversized params + 201-item report, interleaved-audit isolation,
bypass (internal tool name, raw string args), status-leak scan, error-map
unit checks.

## Protocol Tests
Handshake echo + unknown-version fallback, tools/list shape + secrecy,
ping, unknown-method code, batch rejection, non-object rejection,
malformed-JSON code, oversized-line drop, notification silence, clean
EOF shutdown, deterministic serialization (sorted keys), subprocess stdio
E2E (4-in/4-out incl. notification), entry-point + factory checks.

## Fixtures
`MockMcpClient` (initialize/list/call + transcript log); Core-model
fixtures reused for candidate/finding payloads. No network, no SDK.

## Files Inspected
- `mcp/server.py` (Phase-11 stub — replaced), `mcp/__init__.py`,
  `cli/main.py` (mcp/report commands), `core/service.py`,
  `core/reporting.py`, `core/verification.py`, `core/policy.py`,
  `core/tool_registry.py`, `core/correlation.py`, `core/findings.py`
- `pyproject.toml` (scripts/deps), `docs/16/02/03`, `docs/schemas/*`
- prior unit tests (regression surface)

## Files Changed
- `src/emo_cyber_agent/mcp/protocol.py` (NEW): wire framing, versions,
  error codes, 1 MiB cap.
- `src/emo_cyber_agent/mcp/tools.py` (NEW): 5 tools, schemas, token-key
  screen, shape validator.
- `src/emo_cyber_agent/mcp/delegate.py` (NEW): Core delegation ×5,
  output redaction, error mapping, sanitized logs.
- `src/emo_cyber_agent/mcp/server.py` (REPLACED stub): stateless
  dispatcher + stdio loop + factory.
- `src/emo_cyber_agent/cli/main.py` (ADDITIVE): `mcp` runs the server.
- `tests/unit/test_mcp.py` (NEW): 24 offline tests.
- (No Core/policy/adapter/schema changes; no new runtime deps.)

## Schemas
No new public schemas: MCP `inputSchema`s are interface shapes validated
in-adapter; Core contracts (audit-result/report schemas) are reused
unchanged. 5/5 schema files valid (4 legacy + report).

## Invariant Impact
1. Read-only — ENFORCED (read_only forced; verify returns plans).
2. Untrusted content — ENFORCED (escaping + caps + fence/entry checks).
3. No finding without evidence — PROTECTED (report path reuses Core gate).
4. No destructive action — ENFORCED (inexpressible in surface).
5. Tool outputs are evidence — PROTECTED (chain untouched).
6. Uncertainty explicit — PROTECTED (verbatim pass-through).
7. Same contracts — ENFORCED (single delegate→Core path per tool).
8. Provider external — ENFORCED (no SDK in runtime deps).
9. Scanner provenance — PROTECTED (never exposed, never needed).
10. No cross-project reuse — ENFORCED (per-request scoping; isolation tests).
11. Specialist worker — ENFORCED (5 tools; scan-grep clean).
12. Host delegates — ENFORCED (this task IS the delegation interface).
No invariant weakened; adapter adds zero authority by construction
(decision-verb scan of delegate is a test).

## Known Limitations
- `cyber_audit`/`cyber_review` return foundation-stage Core results
  (delegation path is production-shaped; depth arrives with the wired
  audit runner in release integration).
- `cyber_verify` returns policy-gated PLANS; execution wiring is
  per-audit release integration (same stance as ECA-T010).
- No progress/cancellation streaming yet (deferred to host integration).
- Package not pip-installed in this environment (PEP-668 system
  interpreter); validated via CliRunner + subprocess + SDK interop.

## Deferred HTTP/Remote Work
No HTTP server, no remote auth, no resources/prompts surface, no
additional tools beyond the five with real Core contracts.

## Evidence
- `pytest tests/ -p no:warnings` → `262 passed, 3 skipped`.
- `validate_schemas.py` → 5/5 OK. `compileall` → OK.
- Real-SDK interop: `INIT protocol: 2025-06-18 | server: emo-cyber-agent
  0.1.0 / TOOLS: [5 exact names] / STATUS ok: True / AUDIT ok: True /
  INTEROP PASS` (reference `mcp` SDK client over real stdio subprocess).
  NOTE (documentation pin, not a re-execution): `2025-06-18` above is the
  protocol version negotiated with the particular `mcp` SDK build used for
  that interop probe at test time — it is NOT an EMO release date, NOT an
  EMO version, and NOT a claim about the project's current state. The
  server accepts `2024-11-05`, `2025-03-26`, `2025-06-18` and echoes the
  client's version when known, else the latest it supports.
- Subprocess stdio E2E: 4-in/4-out incl. notification silence.
- Files: `mcp/{protocol,tools,delegate,server}.py`, `cli/main.py`
  (+mcp wiring), `tests/unit/test_mcp.py`.

## Final Status
**PASS** — all 24 exit criteria met: installed-package entry point runs
stdio; handshake/list/call verified incl. live SDK; 5 high-level tools
only; audit/review/verify-plan/report/status all delegate to real Core
contracts; no internal exposure; per-request scoping + isolation;
mapped sanitized errors; no secrets/CoT; zero duplicated Core logic;
no bypass/shell; malformed handled; protocol + security + host-fixture
tests green; prior suites + schemas green. No BLOCKED condition (no
bypass, no direct execution, no finding/policy alteration, no cross-audit
access, no secret/filesystem/network exposure) observed. T014 (CLI
universal interface) may proceed.
