# POST-T020 Template Adversarial Review (G5-B, independent, read-only)

Scope: official report_templates set + engine + renderer. All probes live,
in-memory, no file modifications.

| # | Attack | Verdict |
|---|---|---|
| 1 | Field removal (mandatory drop) | RESISTED (validator error + renderer re-add) |
| 2 | Field shadowing | RESISTED (constructor rejects; renderer dedupes; `model_copy` bypass inert) |
| 3 | Malicious headings | RESISTED (md_escape, newline collapse) |
| 4 | Provenance stripping | RESISTED dual-denial on flags; dict-strip downgrades to untrusted (noted) |
| 5 | Verification stripping | RESISTED (mandatory-field error + renderer re-add) |
| 6 | Hidden instructions in template text | RESISTED (zero hits, 19 patterns × 15 files) |
| 7 | Inheritance abuse (fake official) | RESISTED official path (closed IDs, COMPOSITION_INVALID) |

Verdict: **PASS (no BLOCKED findings).**

Hardening (non-blocking, routed to fix batch):
- R1: `Validator.validate` should re-check field allowlists (closes `model_copy` bypass; currently constructor-only).
- R2: `TRUSTED` should not derive solely from self-claimed `provenance['source']`; `Registry.register(trust=TRUSTED)` should verify provenance.
