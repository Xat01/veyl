"""Veyl reporting: turn decided findings into a document.

Nothing here evaluates a rule or computes a risk score. A report is a view onto
conclusions that were already reached and already stored, which is what makes it
reproducible from its inputs and safe to hand to an auditor.
"""

from veyl_reporting.builder import build_context, generate_report
from veyl_reporting.renderers import (
    SEVERITY_ORDER,
    ReportContext,
    render,
    render_html,
    render_json,
)

__all__ = [
    "SEVERITY_ORDER",
    "ReportContext",
    "build_context",
    "generate_report",
    "render",
    "render_html",
    "render_json",
]
