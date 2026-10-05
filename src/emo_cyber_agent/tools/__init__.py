"""Tool registry for EMO-Cyber-Agent.

Provides tool discovery and registration for the cybersecurity sub-agent.
"""

from .registry import ToolRegistry, ToolSpec

__all__ = ["ToolRegistry", "ToolSpec"]