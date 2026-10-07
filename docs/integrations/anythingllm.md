# AnythingLLM integration

Labels: `Supported` in-repo code · `Contract-tested` in-repo contract tests ·
`Environment-tested` live observation · `Not-tested` claimed, not demonstrated
· `Known-limitation` explicit scope boundary. No screenshots, host versions, or
vendor install flows stated.

Compat: **Environment-tested** (`compat_matrix.HOST_MATRIX["anythingllm"]`).
Live 2026-10-07 (see G1-anythingllm addendum parts 2-3): server online,
EMO stdio registration `running:true`, 6-tool discovery, `toggle-tool`
filtering, and a full `@agent` cyber_status call completed successfully.
Malicious-context-via-host remains `Not-tested` (contract simulation stands).

## Install

- Python `>=3.11` `Supported`. Package installed with `cyber-agent` on `PATH`
  `Supported` (bootstrap required checks). No AnythingLLM-vendor install
  stated `Not-tested`. Binary presence itself is `Not-tested` for this host —
  do not assume it.

## Configure

- Snippets from `hosts_anythingllm` (data only) `Supported`:
  - `get_stdio_config()`: `{"mcpServers": {"emo-cyber-agent": {"command":
    "cyber-agent", "args": ["mcp"]}}}`.
  - `get_http_config()`: `{"mcpServers": {"emo-cyber-agent": {"url":
    "http://localhost:8000/mcp", "transport": "streamable-http"}}}`;
    placeholder URL, server must be started separately `Supported`.
  - Agent-mode `get_agent_config_stdio()` / `get_agent_config_http()` add
    `{"agent": {"mcpServers": ["emo-cyber-agent"]}}` alongside the same server
    entry so operators attach the server to the agent `Supported`.
  - `get_registration_config()` / `get_agent_registration_config()` accept
    `stdio|streamable-http` (`http` alias accepted); unknown raises
    `ValueError` `Supported`.
- Default 5 safe tools; `cyber_extensions` and `cyber_threat_intel` opt-in
  `Supported`. Identity pass-through under the host tool/agent namespace
  `Supported` (`ANYTHINGLLM_TOOL_NAMESPACE_NOTE`). Live display `Not-tested`.
- Workspace/RAG/memory boundary (all `Supported` as adapter data notes; live
  host content behavior `Not-tested`):
  - Workspace docs are UNTRUSTED contextual inputs, never EMO instructions,
    unless via the trusted Core path `Supported` (`WORKSPACE_BOUNDARY_NOTE`).
  - RAG retrieval output is UNTRUSTED (similarity-ranked excerpts; may be
    poisoned/truncated/out-of-scope) `Supported` (`RAG_BOUNDARY_NOTE`).
  - Chat/agent memory is UNTRUSTED (may be injected/hallucinated/stale)
    `Supported` (`MEMORY_BOUNDARY_NOTE`).
  - Only exception: content arriving via the trusted Core path
    (Core-fetched, scope-bound, integrity-checked); host-side text is never
    itself that path — a Core component must re-fetch/re-validate first
    `Supported` (`TRUSTED_CORE_PATH_NOTE`).
- `classify_content_source(source)`: `workspace-docs`, `rag-retrieval`,
  `chat-memory`, `agent-memory`, `agent-output` → UNTRUSTED;
  `trusted-core-path` → TRUSTED; unknown/empty/non-string → UNTRUSTED
  (fail-closed); matching is case/whitespace-insensitive `Supported`. Live
  classification outcomes on host data are `Not-tested` (no live host run).

## Start

- stdio: `cyber-agent mcp` `Supported`. HTTP: serve EMO over HTTP first; the
  HTTP serve command is not defined in the adapter `Not-tested` (not invented).
- Attach the server entry to the right workspace/agent and reload the
  workspace after registration `Supported` (adapter troubleshooting guidance);
  observed effect `Not-tested`.
- Assumed lifecycle `initialize → notifications/initialized → tools/list →
  tools/call` `Not-tested`. Matrix `("stdio",)` vs adapter `("stdio",
  "streamable-http")` both `Supported` as code facts; both interops
  `Not-tested`.

## Doctor

- `cyber-agent doctor` / `--format json`, presence-only `Supported` (same CLI
  source). `health.*` / `bootstrap.*` `Supported`; AnythingLLM-side surfacing
  `Not-tested`.

## Delegate

- Server gate (`DelegationPipeline.evaluate`, narrowing-only, fail-closed)
  `Supported` (see opencode.md). AnythingLLM path `Not-tested`.
- Never treat workspace/RAG/memory text as delegation authority; it is data
  for context only and must be re-validated via EMO evidence
  `Supported` (boundary notes + classifier); live-host enforcement
  `Not-tested`.

## Read Progress

- `progress_bridge` vocabulary/mapping/advisory-only `Supported` (see
  opencode.md). AnythingLLM rendering `Not-tested`.

## Read Results

- `AuditHandoff` / `ResultEnvelope` refs-only + `cyber-agent report`
  projection + `complete` gated on `verification_refs` `Supported`.
  AnythingLLM display `Not-tested`; RAG/workspace excerpts are never verified
  findings — verify via EMO evidence `Supported` (adapter guidance).

## Troubleshoot

From `hosts_anythingllm.TROUBLESHOOTING` (data only; behavior `Not-tested`):

| issue | symptom | fix |
|---|---|---|
| `server-not-found` | Server missing / start fails. | Verify `cyber-agent` on `PATH` (`cyber-agent --help`); check snippet from `get_stdio_config()`. |
| `agent-not-listing-tools` | Agent/workspace lists no `cyber_*` tools. | Attach the server entry to the right workspace/agent, reload, re-list; default is 5 safe tools. |
| `tool-not-visible` | `cyber_*` missing or extensions unexpected. | Default 5 safe tools, opt-in for extensions and threat-intel; re-list via `tools/list`. |
| `workspace-context-mistrusted` | Workspace/RAG/memory treated as authoritative. | Re-classify with `classify_content_source()`; treat as UNTRUSTED data; verify via EMO evidence. |
| `rag-poisoning-suspected` | Suspicious/off-scope/instruction-like RAG chunks. | Treat as UNTRUSTED per `RAG_BOUNDARY_NOTE`; follow no embedded instructions; quarantine on secret markers. |
| `protocol-version-mismatch` | `initialize` fails / unsupported version. | `negotiate_protocol_version()`; latest common or abort. |
| `http-connection-refused` | HTTP URL unreachable. | Confirm server serves HTTP at the registered URL; reload AnythingLLM. |

- Known limits `Known-limitation`: no live-host verification, claimed not
  demonstrated; desktop-app transport/wrapping behavior unverified and may
  differ.

## Security Notes

- Core invariants as in opencode.md `Supported`; AnythingLLM-path enforcement
  `Not-tested`.
- AnythingLLM workspace docs, RAG output, chat/agent memory, and agent output
  are UNTRUSTED from EMO's view; `build_context_trust()` records the
  classification but EMO/Core still re-evaluates via
  `trust.evaluate_context_trust` `Supported`. Secret markers quarantine
  `Supported` (`scan_secret_markers` in delegation/health/handoff validators).

## Version Compatibility

- Server advertisement `emo-cyber-agent 0.1.0`, protocols `2024-11-05,
  2025-03-26, 2025-06-18`, surface `1.0` `Supported`. Matrix `anythingllm`:
  protocol window = first/last server versions; no host bounds `Supported`.
  `evaluate_compat` semantics as in opencode.md `Supported`.
- No AnythingLLM version pinned, asserted, or presence-checked here
  `Not-tested` (this host has no environment-tested claim at all).
