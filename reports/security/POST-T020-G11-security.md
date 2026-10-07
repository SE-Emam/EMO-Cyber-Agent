# POST-T020 G11 — Independent Security Audit (Attack Review)

- Role: G11 Independent Security Auditor. I did NOT write any T020 code.
- Scope: all NEW/CHANGED surface since `v0.1.0` (= uncommitted working tree: T020 track).
- Method: read-only source review + live probes via `PYTHONPATH=src python3` and real
  loopback sockets. No source/test files modified.
- Verdict: **BLOCKED** — 3 Medium findings (see M1, M2, M3).
- Counts: **3 Medium / 4 Low / 3 Info** VULNERABLE-or-residual; all other attacks **RESISTED**.

## Result summary

| # | Attack | Result | Severity | Location |
|---|--------|--------|----------|----------|
| H1 | HTTP foreign Host | RESISTED (403) | — | `src/emo_cyber_agent/mcp/http_server.py:195` |
| H2 | HTTP foreign Origin / `null` / suffix-domain | RESISTED (403) | — | `http_server.py:199` |
| H3 | DNS-rebinding shape (`evil.com`→127.0.0.1, `localhost.` suffix, `0.0.0.0`) | RESISTED (403) | — | `http_server.py:96` |
| H4 | Missing auth / wrong bearer / unset-var | RESISTED (401, fail-closed) | — | `http_server.py:205` |
| H5 | Session replay w/ cross triple | RESISTED (440+quarantine, never dispatched) | — | `http_server.py:160` |
| H6 | Partial triple / empty token / unknown token | RESISTED (400/400/404) | — | `http_server.py:175` |
| H7 | Oversize body (>1 MiB, incl. absurd lengths) | RESISTED (413, bounded drain) | — | `http_server.py:358` |
| H8 | GET /mcp, other methods, bad path, bad JSON | RESISTED (405/404/400) | — | `http_server.py:296,331` |
| H9 | Concurrent cross-talk (20 threads) | RESISTED (no errors, lock-serialized dispatch) | — | `http_server.py:219` |
| H10 | Remote-bind misuse (`0.0.0.0` w/o flag) | RESISTED (`ValueError`, fail closed) | — | `http_server.py:277` |
| H11 | Slow client (lying Content-Length holds thread) | RESIDUAL NOTE | Info | `http_server.py:358` |
| D1 | Filler/hyphen/underscore separators (`hide-the-findings`) | RESISTED | — | `subagent/delegation.py:63,86` |
| D2 | Cross-field split (`disregard` + `previous` in separate fields) | RESISTED (join+collapse rejoins) | — | `delegation.py:141,275` |
| M1 | `disregard`-family narrowness (`disregard the policy`, `-all instructions`, `-prior…`, `do not validate/check`, hyphen/concat forms) | **VULNERABLE** | **Medium** | `delegation.py:73-74`, `subagent/sanitizer.py:52-53` |
| M2 | Homoglyph evasion (e.g. Cyrillic `і` in `dіsregard`; NFKC does not fold confusables; sanitizer also misses) | **VULNERABLE** | **Medium** | `delegation.py:124`, `sanitizer.py` patterns |
| D5 | Word-order swap (`policy ignore…`, `verify do not`) | VULNERABLE (residual) | Low | `delegation.py:70`, `sanitizer.py:48` |
| D6 | `grant … write` padding past `.{0,40}` (pre-existing bound) | VULNERABLE (residual, pre-existing) | Low | `delegation.py:77-78` |
| C1 | Checklist item-impersonation (fake id / case / scope) | RESISTED (`KeyError`, exact match) | — | `checklists/catalog.py:396` |
| C2 | Authority extraction (checklist fed as instructions) | RESISTED (no authority fields, frozen, `extra="forbid"`, prose-only) | — | `checklists/spec.py:44`, `catalog.py` |
| T1 | R1 validator bypass via `model_copy(update=…)` / `model_construct` | RESISTED (re-checked, denied) | — | `report_templates/validator.py:22` |
| T2 | R2 validator minting trust | RESISTED (always `UNTRUSTED`) | — | `validator.py:59` |
| L1 | Registry TRUSTED on self-claimed `provenance.source=="official"` (no authentication; any in-process caller or any YAML file in the loaded dir can claim it) | **VULNERABLE** | Low | `report_templates/registry.py:17` |
| L2 | Dead `XMLHttpRequest` marker (mixed-case vs lowercased haystack: never fires) + spacing variants (`require (`, `fetch (`, `eval (`) | **VULNERABLE** | Low | `validator.py:12,37` |
| P1 | Platform alias over-permissiveness (`win32`↔`windows`) | RESISTED (closed 2-token map; `win64/cygwin/msys/plan9/…` rejected) | — | `extensions/compatibility.py:219` |
| S1 | Dockerfile trigger fix + trigger stuffing | RESISTED (candidates-only, no grant; stuffing only widens suggestions) | Info (precision) | `skills/resolver.py:24,60` |
| E1 | Undeclared dir w/ valid cases swept into dataset | RESISTED (declared-sections-only; ignored, count intact) | — | `evaluation/datasets.py:260` |
| E2 | Manifest-declared ghost section / empty-sections sweep | RESISTED (refused / fail-closed `INVALID_CASE`) | — | `datasets.py:250` |
| M3 | Malicious case content escaping blind projection (nested `input.*.ground_truth` delivered blind; top-level-only key check) | **VULNERABLE** | **Medium** | `evaluation/post_t020_benchmark.py:323,365` |
| B2 | Blind mapping w/ top-level leak fields | RESISTED (refused `BLIND_ACCESS_DENIED`) | — | `post_t020_benchmark.py:383` |
| A1 | Host-adapter config-injection via troubleshooting text | RESISTED (prose-only, no executable config; fix points at function, not pasted config) | — | `subagent/hosts_opencode.py:104`, `hosts_hermes.py` |

## Evidence (live probes)

- HTTP (real socket, `HttpMcpServer` on 127.0.0.1): `GET /mcp`→405; `POST /nope`→404;
  `Host: evil.com`→403; `Origin: http://evil.com`→403; `Origin: null`→403;
  `127.0.0.1.evil.com`, `attacker.localhost.evil.com`, `0.0.0.0`, `localhost.`→403;
  `LOCALHOST`, `[::1]`→200 (correct). No `Authorization`→401; wrong bearer→401;
  lowercase `bearer`→401 (fail-closed); configured-but-unset var→401 even with creds.
  Cross-triple replay→440 `{"quarantine": true, "code": "MCP_SESSION_MAP_TRIPLE_MISMATCH"}`,
  request never dispatched; correct triple→200; partial triple→400; unknown→404;
  empty→400; stateless (no token)→200. 1 MiB+100 B body→413; invalid JSON→400.
  20-thread hammer→0 errors. `start("0.0.0.0")` w/o `allow_remote`→`ValueError`.
  Origin matrix: `http://localhost:3000`, `HTTP://LOCALHOST`, `http://[::1]:8080`→allow;
  `http://localhost.evil.com`, `http://127.0.0.1.evil.com`, `garbage:///`,
  `http://localhost%2eEVIL.com`→403. Server keeps serving legit traffic while one
  lying-`Content-Length` client hangs (H11: thread held until socket timeout; localhost-only).
- Delegation: `hide-the-findings` / `hide_the_findings` / `hide all of the findings`→hit;
  cross-field `disregard\nprevious instructions`→hit; ZERO-WIDTH space→hit (sanitizer
  normalizer folds it); NBSP→hit. Misses (both `scan_hostile` AND `sanitize→allow`):
  `disregard the policy`, `disregard all policies`, `disregard all/prior instructions`,
  `disregard the above`, `do not validate/check`, `never verify anything`,
  `DONOTVERIFY`, `do-not-verify`, `dis-regard previous`, Cyrillic-`і` homoglyphs,
  word-order swaps, `grant` +51 chars+ `write`.
- Checklists: `Secure-Code-Review`, `../x`, `secure-code-review-extra`, `""`,
  `SOURCE-CODE-CHANGE`, trailing-space scope→all `KeyError`. Item keys contain no
  severity/verdict/capability/policy/grant fields; frozen (`ValidationError` on write);
  `from_dict` with injected `severity`→`ValidationError`. No imperative directives in
  text (one regex hit was `…verification runs recorded…`, benign).
- Templates: `model_copy`/`model_construct` hostile fields→`field-invalid` denied (finding
  + section paths). Case variants (`REPORT.title`, `Finding.Title`, padded)→denied.
  `report../x`, `meta.`→allowed (Info: prefix allowlist is syntactic; official specs only
  ever use `report.summary`; worst case an unknown display label, no path execution found).
  Validator returns `UNTRUSTED` even for official-shaped specs. BUT
  `Registry.register(valid_spec_with_provenance_claim, trust=TRUSTED)` succeeds on a
  caller-supplied claim, and `load_official_registry(dir)` confers TRUSTED on any YAML in
  `dir` that claims `source: official` — trust root is the directory, the string check
  authenticates nothing (L1). `XMLHttpRequest` marker can never match (L2).
- Platform: `windows/WINDOWS/win32/WIN32/darwin/linux`→compat; `win64/cygwin/msys/
  windowsnt/freebsd/plan9/win32x`→`platform-unsupported` rejected.
- Skills (builtin registry): `Dockerfile`/`DOCKERFILE`→container-security (fix works);
  stuffing (`Dockerfile`+9 signals, objective stuffing)→only wider candidate list;
  `required_capabilities` returns requested-not-granted (`repository.read`); unknown
  skills skipped. Substring matching over-fires (`not-a-dockerfile.txt`,
  `xDockerfile`, `Dockerfile2` all match) — precision-only, Info.
- Eval loader: planted `evil_section/` with schema-valid case→excluded, 104 cases intact;
  ghost declared section→`DATASET_NOT_FOUND`; emptied `sections`→sweep fail-closed
  (`INVALID_CASE` on foreign-schema `post_t020/` files). `case_count` gate intact.
- Benchmark blind: raw mapping with top-level `expected_signal`→`BLIND_ACCESS_DENIED`;
  typed blind exposes only `case_id/title/category/secondary_categories/kind/input`.
  BUT `input: {…, context: {ground_truth: …, expected_signal: …}}` constructs fine and is
  delivered verbatim (M3). Same shallow-check shape exists in legacy `blind_case`
  (`evaluation/cases.py`), but the T020 projection replicates it in new code.
- Host adapters: all `TROUBLESHOOTING.fix` strings are prose (no backticks/braces/newlines,
  only benign `cyber-agent --help`); opencode fix references `get_registration_config()`
  rather than pasting config; registration snippets are typed data
  (`{"mcp": …}` live shape vs `{"mcpServers": …}` hermes input form).

## Findings (actionable)

- **M1 — Medium — `disregard`/`do-not-verify` patterns are over-narrow literals.**
  `disregard\s+previous` misses the most natural variant (`disregard the policy`) and
  `do\s+not\s+verify` misses `validate/check` synonyms and hyphenated/concatenated forms —
  symmetrically in delegation screen and sanitizer, so no defense-in-depth for this family.
  Fix: generalize to `disregard\s+(the\s+|all\s+|any\s+)?(polic|previous|prior|above|instruction)`-style
  and `do\s+not\s+(verify|verif\w*|validat\w*|check\w*)` (plus hyphen/underscore-tolerant separators),
  mirrored in both modules with regression tests per variant.
- **M2 — Medium — no confusable/homoglyph folding; NFKC-only normalization.**
  Single-script homoglyph (`dіsregard` with Cyrillic і) evades both layers. Fix: add
  confusable folding (e.g. `confusable_homoglyphs` or explicit Cyrillic/Greek→Latin map for
  the hostile alphabet) before matching, or an allowlist-script check that flags mixed-script
  tokens in untrusted metadata.
- **M3 — Medium — `post_t020_blind` / `PostT020Case._no_leak_keys` check only top-level keys.**
  Nested `input.*` objects can carry `ground_truth`/`expected_signal`/`must_not`/`label`/
  `verdict` into system-visible input, breaking the blind-evaluation guarantee and letting a
  poisoned fixture inflate scores that feed security gates. Fix: recursive key scan of `input`
  at construction AND at projection (fail closed), plus deep-copy on projection (currently
  shallow `dict()` shares nested objects with the case).
- L1 — Low — authenticate the TRUSTED root: `load_official_registry` should verify provenance
  against the loader context (pinned directory + digest pinning), and `Registry.register`
  should document that `trust=TRUSTED` is caller-authenticated (consider a private conferral
  path so arbitrary callers cannot mint TRUSTED with a dict claim).
- L2 — Low — fix dead `XMLHttpRequest` marker (lowercase it) and consider whitespace-tolerant
  markers (`require\s*\(`, `fetch\s*\(`, `eval\s*\(`); audit other mixed-case markers.
- L3/L4 — Low — word-order and `.{0,40}` padding residuals; extend with ordered-pair patterns
  and a wider/longer window (with ReDoS-safe bounds) or token-proximity scoring.
- Info — H11 slow-client thread hold (consider read timeouts / max-connections bound even on
  localhost); S1 substring over-triggering (consider basename/extension-anchored matching);
  `report.`/`meta.` prefix syntax (consider closed vocabulary, e.g. `report.summary` only).

## Verdict

**BLOCKED.** Three Medium findings (M1, M2, M3) each independently break a T020 security
property: M1/M2 bypass the newly-added hostile-payload screen with trivial/natural inputs,
and M3 breaks the benchmark blind-delivery guarantee. Top risk is **M3** (silent benchmark
contamination → false confidence in security gates), followed jointly by **M1/M2** (detective-control
evasion on the delegation path). All Mediums must be fixed and re-probed before release;
Lows/Infos are hardening backlog.
