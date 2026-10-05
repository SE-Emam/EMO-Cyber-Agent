"""Core module public interface.

Exposes the FoundationSecurityAuditor and Domain models.
Tool registry is internal to Core.
"""

from .service import FoundationSecurityAuditor as SecurityAuditor

__all__ = ["SecurityAuditor"]