# 08 — Tool Contracts

## Tool capability model

Each tool declares:

```text
name
version
provider
capabilities
risk_level
read_only
requires_authorization
input_schema
output_schema
provenance_fields
```

## Initial adapter families

### Repository

- Local filesystem/git
- GitHub repository/metadata/code/security findings

### Database/platform

- Supabase project/schema/RLS/auth/data-access inspection

### Static analysis

- Semgrep
- CodeQL where available

### Supply chain

- Trivy
- OSV-based dependency scanning

### Secrets

- Gitleaks or equivalent secret detector

## Tool safety classes

### SAFE_READ

Pure read/analysis operation.

### SAFE_VERIFY

Controlled local/test verification with explicit policy allowance.

### WRITE_REMEDIATION

Branch/file/PR/database changes. Disabled by default.

### DESTRUCTIVE

Deletion, irreversible migration, production mutation, or equivalent. Not part of the default product and should require an explicit external approval layer if ever implemented.

## Shell execution

A general unrestricted shell tool MUST NOT be exposed by the default security-agent tool registry. Tool adapters should expose narrow capabilities instead.

## Normalization

Every tool output should be normalized into one or more `EvidenceItem` objects with source, timestamp, location, content hash where possible, and tool provenance.
