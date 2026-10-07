"""EMO-Cyber-Agent public package.

Public API tiers (see ECA-T016 release notes):
- SUPPORTED (stable): SecurityAuditor, ReportService, generate_report.
- PROVISIONAL (usable, may evolve): ReasoningEngine, VerificationService,
  EvidenceStore, SecurityFinding, AuditReport.
- INTERNAL (no compatibility promise): everything else under submodules.
"""

__version__ = "0.2.0"

from .core.reporting import ReportService, generate_report
from .core.service import SecurityAuditor

__all__ = ["SecurityAuditor", "ReportService", "generate_report", "__version__"]

SUPPORTED_API = ("SecurityAuditor", "ReportService", "generate_report", "__version__")
PROVISIONAL_API = (
    "ReasoningEngine",
    "VerificationService",
    "EvidenceStore",
    "SecurityFinding",
    "AuditReport",
)
