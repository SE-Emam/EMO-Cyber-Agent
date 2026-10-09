# POST-T021 Test-Secret Hygiene — T21-K (Test-Key Hygiene Agent)

- Date (UTC): 2026-10-08
- Agent: T21-K
- Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
- Ownership: wrote ONLY this file (`reports/security/POST-T021-test-secret-hygiene.md`). No other files created, modified, or deleted. No logs purged, no fixtures edited — audit truth preserved.
- Subject: locally-generated AnythingLLM test API key created during POST-T020-G1 live testing (test-only). Referred below ONLY as `ak-test-<redacted>` (presence-only). No key value is printed anywhere in this report.
- Safety: all checks were presence/metadata-only (row counts, name lists, length-of-secret-column only where noted, pattern-shape scans). Secret column values were never selected, printed, or exfiltrated.

## 1) Locations checked (per-location FOUND/CLEAR, sans values)

| # | Location | Method (presence-only) | Verdict |
|---|----------|------------------------|---------|
| 1 | Creation point — AnythingLLM app DB | SQLite metadata on `~/Library/Application Support/anythingllm-desktop/storage/anythingllm.db` — table list, `api_keys` column names + `COUNT(*)`, non-secret columns (`id`, `createdBy`, `createdAt`, `lastUpdatedAt`, `name`), `LENGTH(secret)` only; value never selected | **FOUND** — `api_keys` table holds **1 row** (`id=1`, secret length non-zero, `createdBy=NULL`); `browser_extension_api_keys` 0 rows, `temporary_auth_tokens` 0 rows, `password_reset_tokens` 0 rows. This is `ak-test-<redacted>` at rest in the app DB, matching the POST-T020-G1 note ("one API key generated during testing remains in app DB"). |
| 2 | Tracked files (`git grep`, tracked only) | `git grep -i -E "api[_-]?key|bearer"` (133 hits reviewed by shape) + `git grep -E "sk-[A-Za-z0-9]{8,}"` (8 hits); `git log -S "api_keys"` (empty) | **CLEAR** — all hits are code patterns (firewall regexes, bearer-auth logic, mock fixtures), docs prose, or synthetic markers (`sk-injected` in `tests/unit/subagent/test_e2e_matrix.py`, `SUPERSECRETVALUE999` mock). No AnythingLLM-issued key material in tracked files. `sk-` hits are false-positive substrings (`task-unverified`, `risk-metadata`, `official-task-extension`). No `anythingllm.db` or `.env` is tracked (`git ls-files` shows only docs/src/tests paths). |
| 3 | Test fixtures (`tests/fixtures`) | Regex scan for real-key shapes (`sk-…16+`, `AKIA…`, `xox…`, `ghp_…`, `gsk_…`) — 2 hits, context-shape review with values redacted | **CLEAR** (of `ak-test-<redacted>`) — the 2 `ghp_…` hits are pre-existing synthetic fixtures (`security_knowledge/knowledge_records.json`, `tool_packs/secret-stdout.json`), unrelated to AnythingLLM. No AnythingLLM test-key material in fixtures. |
| 4 | Shell history (`~/.zsh_history`, 3907 lines) | `grep -i anythingllm` → 0 lines; `grep -i -E "api-key|apikey|api/key|generate.*key"` → only unrelated lines (other-project provider-config greps) | **CLEAR** — no generation command and no VALUE present in shell history. |
| 5 | Logs — `reports/development/POST-T020-G1-anythingllm.md` + `reports/security/POST-T021-anythingllm-adversarial.md` | Regex for `secret|api_key|bearer|token\s*[:=]\s*\S{20,}` (value-shape) → 0 hits in both; phrase `api key` appears 4× / 1× as prose only | **CLEAR / SANITIZED** — presence-only references ("one API key generated … remains in app DB", "user may delete it in Settings → API Keys"); no values logged. |
| 6 | Screenshots | `assets/` + repo `*.png/*.jpg` search (excl. `.venv`) → only `assets/banner.png`, `assets/logo.png` (repo branding) | **CLEAR** — none expected, none found; no test screenshots exist. |
| 7 | Env files (repo `.env*`) | `ls .env*` → no matches; `git status .env*` → no matches | **CLEAR** — repo env files untouched/nonexistent; nothing written there. |
| 8 | AnythingLLM server `.env` at rest (`…/storage/.env`, 25 lines) | Key-NAME list only (`cut -d= -f1`); empty/non-empty flags only, values never printed | **NO `ak-test-<redacted>` PRESENT** — provider-name keys observed (`OPEN_AI_KEY` non-empty, `GENERIC_OPEN_AI_API_KEY` non-empty placeholder-length, `LLM_PROVIDER`, `GENERIC_OPEN_AI_*`, `SIG_KEY`/`SIG_SALT` non-empty). These are server/provider config slots, not the dev-API-key row (§1). No test-key value in this file; no value reproduced here. |

## 2) Boundary-crossing assessment

- `ak-test-<redacted>` (the local dev API key in §1): **never crossed a boundary**. Evidence: CLEAR in §§2–7 (not in tracked files, fixtures, history, logs, screenshots, or repo env); POST-T020-G1 transcripts confirm temp files shredded and no key material printed. It resides ONLY in the local app DB on the operator machine.
- Distinguished material — provider credentials used for the quota-approved live loop (user-supplied kiosapi/groq key, wired via generic-openai, reverted after per POST-T020-G1 addenda parts 3–4): also **never printed or committed** per those transcripts ("Key never printed; temp files shredded"; ".env restored byte-identical"). At rest today the server `.env` shows provider-name slots occupied (see §8) — treated as operator-owned config, not exfiltrated, not reproduced here. No finding that any credential value crossed to a third party, log, or repo file.
- Net: **no secret-value boundary crossing found** for either the test key or the provider key in the locations checked.

## 3) Rotation outcome

- App state probe (this session): no `anythingllm` process (`ps` clean), port 3001 **connection-refused** (`nc` exit 1), `curl http://127.0.0.1:3001/api/ping` → **http_code `000`, curl exit 7**; MCP config at rest `{"mcpServers": {}}` (clean). The app is **DOWN**.
- Verdict: **ENVIRONMENT-BLOCKED** for the rotation step. The official-path deletion (Settings → API Keys via the operator session) and the presence-safe old-key-dead check (authenticated endpoint → expect **401**, record status only) cannot be executed while the backend is down, and this agent did not launch the app (no state change).
- Old-key-dead proof: **NOT OBTAINED** (env-blocked; no authenticated call attempted against a down port — any value-bearing request would be pointless and unsafe).
- Exact next operator step (one-liner): `open -a AnythingLLM` (wait for port 3001), then in Settings → API Keys delete key `id=1` (`ak-test-<redacted>`), then re-probe `curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <old-key-held-only-in-operator-session>" http://127.0.0.1:3001/api/<auth-endpoint>` and confirm `401` without printing the key.

## 4) Residual risk

- **Residual risk: LOW but OPEN — single test-only dev key (`ak-test-<redacted>`, `api_keys.id=1`) persists in the local AnythingLLM SQLite DB on the operator machine until the operator performs the one-liner above; exposure is confined to local disk (no repo/history/log/fixture/env spread found), so risk is local-access-only, closed fully on deletion + 401 proof.**
