# 05 — MCP Interface Contract

## Transport

Primary: MCP over stdio.

Optional later adapter: MCP over HTTP for remote execution.

## Design principle

Expose **high-level specialist capabilities**, not the complete low-level scanner toolbox, to the host agent.

## Proposed tools

### `cyber_audit`

Purpose: full or scoped security audit.

Input:

- `target`: local path or approved repository reference;
- `scope`: include/exclude patterns and resources;
- `mode`: `quick | standard | deep`;
- `permission_profile`: `read_only | verify | remediate`;
- `focus`: optional list of security domains.

Output: `AuditResult`.

### `cyber_review`

Purpose: focused review of provided code/context.

Input:

- target/context;
- review type;
- file/location hints;
- permission profile.

Output: findings plus evidence references.

### `cyber_verify`

Purpose: verify a specific finding using only policy-approved actions.

Input:

- `finding_id`;
- verification scope;
- permission profile.

Output: verification object and updated finding state.

### `cyber_supabase_audit`

Purpose: review Supabase schema, RLS, auth/data-access relationships, and edge functions when configured.

Default: read-only.

### `cyber_dependency_audit`

Purpose: inspect dependencies and known vulnerability metadata.

### `cyber_secret_audit`

Purpose: detect probable secrets without returning secret values.

### `cyber_status`

Purpose: return job status, policy version, and tool availability without exposing credentials.

## Error contract

Errors should include:

- stable error code;
- safe human message;
- recoverability;
- related audit/job ID;
- no secret material.

## Compatibility

MCP tool names and input/output schema versions are part of the compatibility contract. Breaking changes require a versioned migration plan.
