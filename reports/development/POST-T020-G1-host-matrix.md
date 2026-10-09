# POST-T020 G1 Host Matrix (Lead synthesis)

Verdict: **PASS-WITH-NOTES.**

| Host | Binary | Discovery | Delegate | Filter | Notes |
|---|---|---|---|---|---|
| OpenCode 1.18.34 | ENV | ENV (connected) | ENV (`cyber_status` via run) | ENV (6 vs 5) | Adapter config shape + naming FIXED post-test |
| Pi 0.84.4 | ENV | ENV-negative (no native MCP) | BLOCKED (no MCP, provider offline) | N/A | Environmental, not product |
| Hermes v0.21.4 | ENV | ENV (6/6, connected) | BLOCKED (no provider auth) | ENV (4 filter views) | Key-case note FIXED |
| Jan 0.8.4 | ENV | ENV (stdio 6/6) | BLOCKED (no models/CLI path) | CONTRACT | Environmental |
| AnythingLLM | ENV (Desktop app) | ENV (running:true, 6 tools) | ENV (7 live calls incl. adversarial refused/inert) | ENV (toggle-tool) | Full loop proven 2026-10-07; matrix upgraded to ENVIRONMENT-TESTED |

No crashes, no widening, no leakage, no cross-session contamination in any
live path. Delegation BLOCKEDs are all missing-provider/binary-side, never
EMO-side. Adapter drift fixed + covered by updated contract tests.
Per-host reports: POST-T020-G1-{opencode,pi,hermes,jan,anythingllm}.md.
