# POST-T021 Android HTTP Transport — A5 Report

Date (UTC): 2026-10-08
Agent: A5 (Android HTTP Agent)
Device: emulator-5554 | Termux `cyber-agent` (emo-cyber 0.2.0, entry point `cyber-agent`, module `emo_cyber_agent`)
Transport under test: stdlib Streamable HTTP (`emo_cyber_agent.mcp.http_server.HttpMcpServer`, `POST /mcp`)
Precondition: A2=PASS (package present in Termux; binary name corrected to `cyber-agent` during probing)

## Verdict: PASS

HTTP path works end-to-end on-device with all validations intact. No bypass, no leak, no NOT-EXECUTED case on the required path. Server lifetime was short (single probe run, ephemeral loopback port); always shut down; never exposed beyond localhost (non-local bind refused, shutdown verified by connection-refused).

## Gate A5 decision: PASS

PASS iff HTTP path works with validations intact — met (28/28 live probes PASS, 0 FAIL).
Any bypass/leak = BLOCKED — none observed (Host/Origin/auth/session/triple/size guards all held; safe-call response scanned, no secret material).

## Method (sanitized)

- Started `HttpMcpServer` inside Termux on `127.0.0.1:0` (ephemeral port; actual: 127.0.0.1:35321, run 1).
- Drove it with stdlib-only raw-socket/JSON-RPC probes (exact Host/Origin control; no host-side port forward needed; no public endpoints).
- Separate second `HttpMcpServer` instance (ephemeral loopback port) with `bearer_env_var="A5_PROBE_BEARER"` for auth probes; token was a random per-run value, never a real secret, cleared after use.
- Session probes used a synthetic `SubagentSession` (`a5-*` ids, 10-min TTL); no real audit/project data.
- Both servers stopped in `finally`; post-stop connection-refused verified.

## Per-probe evidence (all executed LIVE on-device; none NOT-EXECUTED except the noted sub-aspect of T14)

| ID | Probe | Expect | Got | Result |
|----|-------|--------|-----|--------|
| T0 | localhost default binding | bind 127.0.0.1, ephemeral port | `bind=127.0.0.1 port=35321` | PASS |
| T1 | initialize (`protocolVersion 2025-06-18`) | 200 + `protocolVersion` + serverInfo | 200, `emo-cyber-agent` present | PASS |
| T2 | notification `notifications/initialized` (no id) | 202 | 202 | PASS |
| T3 | discover (`tools/list`) | 200, tool catalog | 200, 7 tools incl. `cyber_status` | PASS |
| T4 | minimal safe call `tools/call cyber_status {}` | 200 + content, no secret leak | 200 in 0.04 s, leak-scan False | PASS |
| T5a | progress inline (no Accept header, `progressToken`) | 200 JSON array, notifications before response | array=True, notif=True, id=4 terminal | PASS |
| T5b | progress SSE (`Accept: text/event-stream`) | 200 with `event: notification` + `event: message` | both frames present | PASS |
| T6 | `GET /mcp` | 405 (no SSE-primary) | 405 | PASS |
| T7 | `POST /nope` | 404 | 404 | PASS |
| T8a | valid Host (`127.0.0.1:port`) | 200 | 200 | PASS |
| T8b | invalid Host (`evil.example`) | 403 (DNS-rebinding guard) | 403 | PASS |
| T9a | Origin absent (non-browser) | 200 | 200 | PASS |
| T9b | valid Origin (`http://127.0.0.1:port`) | 200 | 200 | PASS |
| T9c | foreign Origin (`https://evil.example`) | 403 | 403 | PASS |
| T9d | Origin `null` | 403 | 403 | PASS |
| T10 | oversized body (1,048,733 B > 1 MiB cap) | 413 | 413 | PASS |
| T11a | auth configured but env var unset | 401 fail-closed | 401 | PASS |
| T11b | wrong Bearer value | 401 | 401 | PASS |
| T11c | malformed scheme (`Token <value>`) | 401 | 401 | PASS |
| T11d | correct Bearer (positive control) | 200 | 200 | PASS |
| T12a | unknown session token | 404 | 404 | PASS |
| T12b | stale/mismatched triple (wrong audit id) | 440 + `quarantine:true`, never dispatched | 440, quarantine=True | PASS |
| T12c | partial triple (1 of 3 headers) | 400 | 400 | PASS |
| T12d | correct triple (positive control) | 200 | 200 | PASS |
| T13 | reconnect (fresh initialize + ping after all traffic) | 200/200 | 200/200 | PASS |
| T14 | timing: 3× ping latency; socket timeout configured | fast; server-stall enforcement NOT-EXECUTED (no hanging-Core fixture; would require blocking dispatch) | max 0.00 s, `sock_timeout=30.0s` | PASS (client-observed) / NOT-EXECUTED (stall sub-aspect) |
| T15 | non-local bind `0.0.0.0` without `allow_remote` | `ValueError` refusal, no socket opened | refused | PASS |
| T16 | shutdown: connect after `stop()` | connection refused | refused | PASS |

Raw probe log: 28 `PROBE ... PASS` lines, 0 FAIL/ERROR, terminated by `PROBE DONE`. (Full stdout retained in the A5 working transcript; no secrets present — only synthetic `a5-*` ids and a discarded random bearer.)

## Validation failures: none

Every negative probe returned the specified fail-closed status (403/401/404/400/413/440/405); positive controls (T11d, T12d, T13) confirm no over-blocking. No secret material in any response body (case-insensitive scan for secret/password/api_key/bearer in T4).

## Notes / deviations

- Brief name correction: the Termux-installed 0.2.0 entry point is `cyber-agent` (not `emo-cyber`); module import is `emo_cyber_agent` (not `emo_cyber`). CLI `mcp` is stdio-only, so the HTTP server was started via the in-package `HttpMcpServer` API — same class the CLI transport composes.
- T14 server-stall timeout is NOT-EXECUTED as a sub-aspect (honest scope limit); it does not affect GATE A5 since the timeout path was partially evidenced (30 s socket timeout configured, sub-second observed latency) and every required validation probe executed live.
- Ownership respected: no `src/` edits, no other files touched; this report is the sole write.
