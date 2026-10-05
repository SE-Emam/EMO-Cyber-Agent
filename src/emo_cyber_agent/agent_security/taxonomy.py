"""Agent threat taxonomy + framework mappings — POST-RC-010.

Closed 25-category taxonomy derived from current agentic security
guidance. Framework mappings (OWASP Agentic / MCP / Skills, MITRE
ATLAS, CAPEC/CWE) are informative metadata: unknown mappings stay
null/UNKNOWN, never invented.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.agent_security.spec import AGENT_THREAT_CATEGORIES

# Informative metadata only. None of these strings drive rules.
FRAMEWORK_MAPPINGS: dict[str, dict[str, Any]] = {
    "GOAL_HIJACKING": {"owasp_agentic": "goal-hijacking", "atlas": None, "capec": None, "cwe": None},
    "PROMPT_INJECTION": {"owasp_agentic": "prompt-injection", "atlas": "AML.T0051", "capec": None, "cwe": None},
    "INDIRECT_PROMPT_INJECTION": {"owasp_agentic": "indirect-prompt-injection", "atlas": None, "capec": None, "cwe": None},
    "TOOL_MISUSE": {"owasp_agentic": "tool-misuse", "atlas": None, "capec": None, "cwe": None},
    "TOOL_POISONING": {"owasp_agentic": "tool-poisoning", "owasp_mcp": "tool-poisoning", "atlas": None, "capec": None, "cwe": None},
    "CONTEXT_SPOOFING": {"owasp_mcp": "context-spoofing", "atlas": None, "capec": None, "cwe": None},
    "DATA_POISONING": {"owasp_agentic": "data-poisoning", "atlas": "AML.T0020", "capec": None, "cwe": None},
    "IDENTITY_ABUSE": {"owasp_agentic": "identity-abuse", "atlas": None, "capec": None, "cwe": None},
    "PRIVILEGE_ABUSE": {"owasp_agentic": "privilege-abuse", "atlas": None, "capec": None, "cwe": None},
    "SCOPE_CREEP": {"owasp_mcp": "scope-creep", "atlas": None, "capec": None, "cwe": None},
    "CREDENTIAL_EXPOSURE": {"owasp_mcp": "token-exposure", "atlas": None, "capec": None, "cwe": "CWE-200"},
    "SECRET_EXPOSURE": {"owasp_mcp": "secret-exposure", "atlas": None, "capec": None, "cwe": "CWE-200"},
    "SENSITIVE_DATA_EXFILTRATION": {"owasp_agentic": "sensitive-data-exfiltration", "atlas": "AML.T0024", "capec": None, "cwe": None},
    "UNTRUSTED_MEMORY": {"owasp_agentic": "memory", "atlas": None, "capec": None, "cwe": None},
    "MEMORY_POISONING": {"owasp_agentic": "memory-poisoning", "atlas": "AML.T0020", "capec": None, "cwe": None},
    "INSECURE_DELEGATION": {"owasp_agentic": "delegation", "atlas": None, "capec": None, "cwe": None},
    "SUBAGENT_CONFUSION": {"owasp_agentic": "subagent-confusion", "atlas": None, "capec": None, "cwe": None},
    "EXCESSIVE_AGENCY": {"owasp_agentic": "excessive-agency", "atlas": None, "capec": None, "cwe": None},
    "UNBOUNDED_AUTONOMY": {"owasp_agentic": "unbounded-autonomy", "atlas": None, "capec": None, "cwe": None},
    "OUTPUT_INJECTION": {"owasp_agentic": "output-injection", "atlas": None, "capec": None, "cwe": "CWE-116"},
    "SUPPLY_CHAIN": {"owasp_agentic": "supply-chain", "atlas": None, "capec": None, "cwe": None},
    "MCP_AUTHORIZATION": {"owasp_mcp": "authorization", "atlas": None, "capec": None, "cwe": "CWE-862"},
    "MCP_SERVER_TRUST": {"owasp_mcp": "server-trust", "atlas": None, "capec": None, "cwe": None},
    "MCP_RESOURCE_TRUST": {"owasp_mcp": "resource-trust", "atlas": None, "capec": None, "cwe": None},
    "MCP_PROMPT_TRUST": {"owasp_mcp": "prompt-trust", "atlas": None, "capec": None, "cwe": None},
}


def framework_mapping(category: str) -> dict[str, Any]:
    """Return metadata mapping; unknown categories stay null, never invented."""
    if category not in AGENT_THREAT_CATEGORIES:
        raise ValueError(f"threat category not allowed: {category}")
    return dict(FRAMEWORK_MAPPINGS.get(category, {"owasp_agentic": None, "atlas": None, "capec": None, "cwe": None}))


def categories() -> tuple[str, ...]:
    return AGENT_THREAT_CATEGORIES
