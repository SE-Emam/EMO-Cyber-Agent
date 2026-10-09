# Security Policy

EMO-Cyber-Agent is a security analysis tool and must itself be treated as security-sensitive software.

## Reporting a vulnerability

Do not publish exploit details, proof-of-concept code, or affected
data for an unpatched issue in the public issue tracker.

- If GitHub private vulnerability reporting is enabled for this
  repository, use **Security → Advisories → Report a vulnerability**
  (preferred: keeps details private until a fix ships).
- Otherwise, open a public issue titled `Security report` containing
  **no technical details**, and ask the maintainers for a private
  channel. A maintainer will follow up with one.

Include, through the private channel: affected version(s), a minimal
reproduction, the security boundary you believe is violated, and the
impact you assess. You will receive acknowledgment and remediation
status there.

## Security boundaries

The default product is read-only. Tool adapters must not assume that code execution is permitted merely because the host is a coding agent.
