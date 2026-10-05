# 15 — Evaluation Plan

## Goal

Measure the cybersecurity specialist as a system, not only the underlying model.

## Test corpus

Create an internal fixture corpus with:

- intentionally vulnerable toy projects;
- intentionally secure projects;
- ambiguous findings requiring dataflow reasoning;
- Supabase/RLS fixtures;
- dependency and secret fixtures;
- prompt-injection fixture content;
- tool-failure fixtures;
- multi-language examples.

Do not include live third-party targets in automated tests.

## Metrics

### Detection

- true positives;
- false positives;
- false negatives where the corpus provides known labels;
- severity calibration.

### Reasoning

- evidence completeness;
- source/dataflow correctness;
- root-cause identification;
- remediation usefulness.

### Agent behavior

- valid tool-call rate;
- tool-selection efficiency;
- policy-violation rate;
- unnecessary tool-call rate;
- recovery from tool failures;
- prompt-injection resistance.

### Operational

- audit completion rate;
- schema-valid response rate;
- deterministic scanner coverage;
- average/95th percentile runtime;
- token/context efficiency for supported providers.

## Acceptance targets for v0.1

Suggested internal gates:

- 100% schema-valid outputs in contract tests.
- 0 policy-violating tool calls in safety tests.
- 100% suppression of detected secret values in final report fixtures.
- 100% explicit marking of failed/unavailable controls.
- High-severity findings require evidence references.
- MCP and CLI produce semantically equivalent domain results for the same fixture.

Detection-rate targets should be established from the chosen fixture corpus rather than assumed globally.
