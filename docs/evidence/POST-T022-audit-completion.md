# POST-T022 — Audit Completion Engine (control catalog v1)

## Decision

PASS for implementation. `audit` completes under a versioned, narrow,
explicitly documented control catalog; every gap stays `partial`.

## What changed

- New `src/emo_cyber_agent/core/control_catalog.py` (`emo-controls-v1`):
  `C-001 secret-exposure` via Gitleaks. Observation → suspected
  high-severity finding (CWE-798), confidence 0.75 (single scanner,
  uncorroborated), linked to its redacted evidence item. `info` and
  untraceable observations cannot occur by construction (native enum has no
  `info` from Gitleaks; findings require evidence ids).
- `core/service.py::audit` returns `completed` (with `completed_at`,
  coverage 1/1, findings, catalog summary in metadata) only when every
  catalog control evaluated and no failures; all previous fail-closed paths
  (unavailable/denied/failed scanner, truncated output, caller policy
  denial, unexpected exceptions) return `partial` unchanged.
- `review` and `verify` remain partial stubs (out of scope, documented in
  the audit docstring).

## Honesty bounds

- v1 coverage is one control. A clean result proves "no secrets found by
  Gitleaks", not "secure". Limitations state this on every completed result.
- Semgrep, Trivy, OSV-Scanner: out of scope, recorded in coverage notes.
- Severity `high` for secrets is a documented policy choice (credential
  compromise material), findings stay `suspected` until verified.

## Verification

- `ruff check src tests scripts`: clean.
- `mypy src` (strict): clean, 254 files (new module included).
- Full suite: green (including 4 updated scanner tests, 3 new catalog
  tests, and unchanged fail-closed CLI/release offline tests).
- `scripts/validate_schemas.py`: 36/36 (no schema change; status enum
  already admitted `completed`).
- Live: `cyber-agent audit . --format json` on this repository returns
  `completed` with Gitleaks 8.30.1 evidence and suspected findings for the
  repo's own test canaries — the engine eats its own dogfood.
