# 14 — Safety and Guardrails

## Permission profiles

### read_only

Allowed:

- read source;
- inspect repository metadata;
- run non-destructive scanners;
- inspect configured platform metadata;
- generate reports.

Not allowed:

- modify files;
- push branches;
- merge PRs;
- mutate databases;
- delete resources.

### verify

Adds narrowly scoped, non-destructive verification in local/test environments where supported by the tool adapter and policy.

### remediate

Reserved for a later milestone. Any implementation should require an explicit approval object and should default to an isolated branch/worktree.

## Policy checks before tool invocation

```text
request → scope check → capability check → permission check
        → target/environment check → redaction check → invoke
```

## Secure defaults

- no production database writes;
- no unrestricted command execution;
- no secret values in final reports;
- no cross-project state reuse;
- no implicit external network targets;
- no automatic remediation.

## High-impact finding rule

Critical/high findings SHOULD be independently reviewed by a second reasoning pass or deterministic evidence source before being marked confirmed, subject to the task and tool availability.

## Audit completeness

A clean-looking report with missing controls is not a clean audit. Completeness must be visible in the report.
