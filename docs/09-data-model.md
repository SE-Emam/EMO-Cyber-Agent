# 09 — Data Model

## Core entities

### AuditJob

Represents one audit execution and its lifecycle.

### Asset

A source file, repository, database object, endpoint definition, workflow, dependency or other security-relevant object.

### EvidenceItem

A discrete observation with provenance.

### Hypothesis

A security hypothesis under investigation. It may be supported, refuted, or unresolved.

### Finding

A normalized security issue derived from evidence and analysis.

### Verification

A record of attempts to establish or refute a finding under policy.

### ToolInvocation

An immutable-ish record of a tool call, status, duration, and safe metadata.

### AuditReport

Human-readable and machine-readable aggregation of the audit.

## Relationships

```text
AuditJob
 ├── Assets
 ├── ToolInvocations
 ├── EvidenceItems
 ├── Hypotheses
 └── Findings
       └── Verifications
```

## Important separation

`EvidenceItem` is not a `Finding`. An evidence item may contribute to zero, one, or many findings. A finding is a reasoned security claim with uncertainty and impact.
