# 16 — Full Implementation Plan

## Phase 0 — Foundation

Deliver:

- packaging;
- repository layout;
- configuration model;
- logging;
- domain identifiers;
- JSON Schema validation;
- test harness.

Exit criteria:

- `pip install -e .` works;
- `cyber-agent doctor` skeleton works;
- schema tests pass.

## Phase 1 — Domain core

Implement:

- AuditJob;
- Asset;
- EvidenceItem;
- Finding;
- Verification;
- ToolInvocation;
- AuditResult;
- domain state machine.

Exit criteria:

- unit tests cover state transitions and validation;
- invalid state transitions rejected.

## Phase 2 — Policy engine

Implement:

- permission profiles;
- scope rules;
- tool capability checks;
- approval primitives;
- untrusted-content classification.

Exit criteria:

- unauthorized tool calls rejected deterministically;
- read-only policy cannot reach write-capable tool.

## Phase 3 — Tool registry and adapter protocol

Implement:

- ToolSpec;
- registry;
- invocation wrapper;
- timeouts;
- error normalization;
- evidence normalization.

Exit criteria:

- fake tools can be registered and invoked in tests;
- failure states are preserved.

## Phase 4 — Deterministic scanners

Implement adapters for initial scanner set:

- Semgrep;
- Trivy;
- OSV;
- Gitleaks;
- CodeQL optional integration.

Exit criteria:

- fixture projects produce normalized evidence;
- versions and failures captured.

## Phase 5 — Repository integrations

Implement:

- local git/filesystem;
- GitHub adapter;
- read-only repository metadata/code/security results.

Exit criteria:

- audit can run from local path and approved GitHub target;
- credentials are never included in evidence/report.

## Phase 6 — Supabase integration

Implement read-only inspection of:

- project metadata;
- schema;
- tables/views/functions;
- RLS and policies;
- auth/data-access metadata where available.

Exit criteria:

- Supabase fixture/e2e tests pass;
- project scoping enforced.

## Phase 7 — Agent reasoning loop

Implement provider abstraction and the agent loop:

- context builder;
- tool planning request;
- structured tool-call parser;
- observation ingestion;
- hypothesis tracker;
- stopping rules.

No specific model is bundled.

Exit criteria:

- fake provider can drive multi-step tool loop;
- tool-call errors recover safely;
- policy is enforced on every action.

## Phase 8 — Security reasoning and correlation

Implement security-specific reasoning workflows:

- auth/authz;
- dataflow;
- Supabase/RLS cross-check;
- business logic;
- scanner triage;
- deduplication;
- confidence calculation rules.

Exit criteria:

- known fixture findings are normalized without duplicates;
- hypotheses can be marked supported/refuted/unresolved.

## Phase 9 — Verification layer

Implement safe verification interfaces:

- static trace verification;
- local/test execution checks where safely available;
- finding lifecycle update.

Exit criteria:

- verification is blocked by read-only policy;
- verification metadata is preserved.

## Phase 10 — Reporting

Implement:

- Markdown report;
- JSON report;
- JSONL event stream;
- summary and completeness sections;
- secret redaction.

Exit criteria:

- all report formats derive from the same domain result;
- schema validation passes.

## Phase 11 — MCP server

Implement:

- stdio server;
- high-level specialist tools;
- typed schemas;
- safe errors;
- server instructions describing read-only defaults.

Exit criteria:

- MCP client can invoke `cyber_audit` end-to-end;
- no internal low-level tool registry leakage unless explicitly designed.

## Phase 12 — CLI

Implement:

- audit;
- review;
- verify;
- scanner commands;
- doctor;
- mcp;
- output formats;
- CI exit codes.

Exit criteria:

- command examples in docs execute against local fixtures.

## Phase 13 — Python API stabilization

Implement typed public API and dependency-injection points.

Exit criteria:

- API can run without MCP or CLI adapters.

## Phase 14 — Security hardening

Perform:

- dependency audit;
- fuzz/negative tests for schemas and tool arguments;
- prompt-injection regression tests;
- secret-redaction tests;
- path traversal/scope tests;
- sandbox/tool permission tests;
- supply-chain review.

Exit criteria:

- no known critical security defect in the agent infrastructure;
- safety acceptance suite passes.

## Phase 15 — Host integration validation

Validate with representative MCP hosts and CLI delegation patterns. Keep integration logic outside the core package.

Exit criteria:

- one MCP registration path per host;
- host receives stable findings;
- unsupported host features fall back to CLI where appropriate.

## Phase 16 — Release candidate

Deliver:

- versioned schemas;
- changelog;
- integration guide;
- security policy;
- reproducible build instructions;
- release checklist.

Exit criteria:

- full test suite passes;
- clean installation from built wheel;
- `cyber-agent doctor` validates required runtime capabilities.
