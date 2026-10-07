# POST-T020 G2 HTTP Transport (Lead synthesis)

Verdict: **PASS.**

- Server (`mcp/http_server.py`, stdlib-only): POST /mcp, SSE notification
  interleave, session-bound triple check (440+quarantine), Host/Origin guards,
  env-ref Bearer, 1 MiB cap, localhost-default. 21 live-socket tests green.
- Clients: full Python flow + reconnect + timeout + shutdown green (10+2);
  opencode/hermes remote-HTTP ENVIRONMENT-TESTED via live discovery;
  pi/jan NOT-ENVIRONMENT-TESTED (no remote flags — honest).
- Security: 24 adversarial cases green, bypasses NONE. Locks: unknown→404,
  mismatch→440+quarantine, wrong auth→401, oversize→413.
- stdio behavior unchanged (import-only check). No new dependencies.
