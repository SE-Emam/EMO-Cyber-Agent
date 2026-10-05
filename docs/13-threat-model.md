# 13 — Threat Model

## Assets

- source code;
- repository metadata;
- database metadata;
- credentials and tokens;
- audit findings;
- audit history;
- model/provider endpoint credentials;
- tool execution environment.

## Threats

### T1 — Prompt injection from repository content

Malicious or accidental instructions embedded in code, README files, issues, fixtures, comments or database text attempt to steer the agent away from policy.

Mitigation:

- untrusted-content classification;
- strong instruction hierarchy;
- no automatic privilege elevation;
- narrow tools;
- evidence provenance.

### T2 — Credential leakage

Tool output or model context may reveal secrets.

Mitigation:

- redaction pipeline;
- secret-value suppression in reports;
- least-privilege credentials;
- short-lived credentials where possible;
- no secret echo in debug logs.

### T3 — Tool misuse

Agent attempts an operation beyond the audit scope.

Mitigation:

- policy engine before every tool call;
- capability declarations;
- read-only default;
- no unrestricted shell tool.

### T4 — False positive / false negative

Reasoning errors cause incorrect security claims.

Mitigation:

- deterministic scanners;
- evidence-first schema;
- second-pass review;
- verification;
- explicit uncertainty;
- regression corpus.

### T5 — Supply-chain compromise

A scanner/plugin/package itself becomes compromised.

Mitigation:

- lock dependencies;
- pin tool versions in deployment;
- record binary/version provenance;
- separate privileged operations.

### T6 — Data exfiltration via model provider

Sensitive code leaves the local trust boundary.

Mitigation:

- explicit provider configuration;
- configurable redaction;
- local/controlled providers supported;
- data-boundary declaration in audit metadata.

### T7 — Cross-project data leakage

Cached evidence from one project is reused in another.

Mitigation:

- audit-scoped namespaces;
- no implicit long-term memory;
- content hashes and project IDs;
- explicit opt-in persistent knowledge stores.

### T8 — Destructive remediation

An agent modifies source or infrastructure when only analysis was requested.

Mitigation:

- read-only default;
- separate remediation mode;
- explicit approval token;
- branch-only write policy as the first write-capable mode.
