"""Report templates package — POST-RC-003 (public surface)."""

from .registry import ReportTemplateRegistry
from .resolver import ReportTemplateResolver
from .service import ReportTemplateService
from .spec import (
    MANDATORY_FINDING_FIELDS,
    ReportTemplatePack,
    ReportTemplateSpec,
    ResolvedReportTemplate,
    TemplateError,
    TemplateErrorCode,
    TemplateSection,
    TemplateTrust,
    VisibilityRule,
)
from .validator import ReportTemplateValidator

__all__ = [
    "MANDATORY_FINDING_FIELDS",
    "ReportTemplatePack",
    "ReportTemplateRegistry",
    "ReportTemplateResolver",
    "ReportTemplateService",
    "ReportTemplateSpec",
    "ResolvedReportTemplate",
    "TemplateError",
    "TemplateErrorCode",
    "TemplateSection",
    "TemplateTrust",
    "VisibilityRule",
    "ReportTemplateValidator",
]
