# 03 — Security Audit Methodology

## Philosophy

The agent follows an evidence-first, layered methodology. Each layer answers a distinct question and produces evidence that feeds later reasoning.

## Phase A — Scope and authorization

1. Identify target and allowed resources.
2. Confirm permission profile.
3. Reject ambiguous external targets when authorization is not established.
4. Record exclusions.

## Phase B — Repository and architecture discovery

Collect:

- languages;
- frameworks;
- package manifests and lock files;
- entry points;
- API routes;
- authentication middleware;
- authorization checks;
- data-access layer;
- infrastructure/configuration;
- CI/CD workflows;
- serverless/edge functions;
- migrations and schema definitions.

Output: attack-surface inventory.

## Phase C — Deterministic scanning

Run permitted tools such as:

- SAST;
- dependency/SCA scanners;
- secret detection;
- IaC/configuration checks;
- repository security findings.

Normalize results into evidence.

## Phase D — Identity and access control

Review:

- authentication boundaries;
- session/token handling;
- authorization decisions;
- object-level access control;
- role/permission checks;
- tenant isolation;
- server/client trust boundaries.

## Phase E — Data access and Supabase

When Supabase is in scope, inspect:

- tables and relationships;
- RLS enabled/disabled state;
- RLS policy coverage;
- auth assumptions;
- views/functions and security context;
- service-role usage;
- storage policies;
- edge functions;
- database functions/procedures;
- exposed columns/data paths.

Cross-check application code against database policy.

## Phase F — Application-layer security

Review by concrete dataflow and trust boundary, including:

- injection families;
- path/file handling;
- SSRF-like server-side fetch boundaries;
- unsafe deserialization;
- template/rendering boundaries;
- command execution boundaries;
- insecure defaults;
- cryptographic misuse;
- unsafe error handling;
- security-sensitive logging;
- rate-limit and abuse controls.

## Phase G — Business logic

Look for security outcomes caused by valid operations used in the wrong combination, including:

- authorization gaps;
- workflow bypass;
- replay or idempotency flaws;
- state transition errors;
- trust of client-controlled values;
- race conditions where observable from code;
- financial/quota/role boundary mistakes.

Business-logic findings require especially strong evidence and clear assumptions.

## Phase H — Supply chain and secrets

Review:

- vulnerable dependencies;
- abandoned/high-risk dependencies where evidence exists;
- lockfile integrity;
- secrets in source/history/config;
- CI/CD secrets exposure;
- unsafe third-party action configuration.

Do not print secret values in reports.

## Phase I — Correlation and de-duplication

Combine scanner findings and model observations by normalized identity:

`location + weakness class + affected component + evidence relationship`.

A deterministic scanner finding is not automatically a confirmed application vulnerability; the agent must assess applicability.

## Phase J — Safe verification

Use verification only when the policy permits it. Verification should prefer non-destructive checks, static tracing, controlled test inputs and local/test environments.

The report must record:

- what was attempted;
- whether it succeeded;
- environment;
- evidence;
- residual uncertainty.

## Phase K — Reporting

Every finding should include:

- severity;
- confidence;
- weakness taxonomy where applicable;
- affected location;
- evidence;
- security impact;
- verification status;
- remediation;
- references;
- limitations.

## Quality gate

A finding is not considered `confirmed` solely because the model is confident. Confirmation requires adequate evidence under the active policy.

## Framework mapping

The methodology is intended to map to recognized software-security concepts such as OWASP, CWE, NIST SSDF and CVSS where appropriate. Exact mappings should be recorded only when justified by the available evidence.
