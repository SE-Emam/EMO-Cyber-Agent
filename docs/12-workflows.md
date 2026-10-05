# 12 — End-to-End Workflows

## Workflow 1: Host agent delegates full audit

```text
Host Agent
   ↓ cyber_audit
EMO scope validation
   ↓
Policy selection
   ↓
Repository inventory
   ↓
Security tool plan
   ↓
Tool execution
   ↓
Evidence normalization
   ↓
Security reasoning
   ↓
Correlation / de-duplication
   ↓
Optional verification
   ↓
Report
   ↓
Return structured AuditResult
```

## Workflow 2: Focused review

```text
Host → cyber_review
      ↓
Identify target files/dataflow
      ↓
Inspect trust boundaries
      ↓
Run narrow deterministic checks
      ↓
Reason over code
      ↓
Return findings
```

## Workflow 3: Supabase-aware audit

```text
Repo code
   +
Supabase schema/RLS/auth metadata
   ↓
Map application identities to database identities
   ↓
Map reads/writes to tables/views/functions
   ↓
Compare expected authorization to RLS/policies
   ↓
Identify cross-boundary authorization gaps
   ↓
Report evidence and assumptions
```

## Workflow 4: Scanner finding triage

```text
Scanner finding
   ↓
Locate source/sink/component
   ↓
Determine reachability/applicability
   ↓
Check compensating controls
   ↓
Classify: likely / false-positive / unresolved
   ↓
Verify when allowed
   ↓
Normalize final finding
```

## Workflow 5: Unknown tool failure

```text
Tool unavailable/fails
   ↓
Record tool failure
   ↓
Continue independent controls
   ↓
Mark affected controls not_evaluated
   ↓
Lower completeness score
   ↓
Never claim clean result for that control
```

## Workflow 6: Prompt-injection detection

```text
Untrusted repository content
   ↓
Parser/content boundary
   ↓
Treat embedded instructions as data
   ↓
Do not elevate privilege
   ↓
Continue security task
   ↓
Optionally emit an agent-integrity observation
```
