"""Report generation.

Two report kinds, and the difference between them is a real one:

* **EXECUTIVE** answers "how exposed are we and is it getting better". It leads
  with business context, counts, and the trend. It contains no rule ids in the
  body prose, because a reader who needs them is the reader for the other report.
* **TECHNICAL** answers "what exactly is wrong and what do I change". Every
  finding carries its rule, its evidence, and its remediation.

Both kinds embed the same evidence. A report is a view onto findings that were
already decided — it never re-evaluates a rule, never re-scores, and never
produces a claim that is not already in the database. That is what makes a
report reproducible from its inputs.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from veyl_api.db.base import utcnow
from veyl_api.enums import (
    ACTIVE_FINDING_STATUSES,
    BusinessCriticality,
    Provenance,
    ReportKind,
    Severity,
)

#: Order severity is presented in. Descending consequence.
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

#: Colour per severity for the HTML report. Red-through-grey reads as
#: "act now" through "informational" without relying on the reader's
#: familiarity with severity vocabulary.
SEVERITY_COLOURS = {
    Severity.CRITICAL: "#b3261e",
    Severity.HIGH: "#d4622a",
    Severity.MEDIUM: "#b8860b",
    Severity.LOW: "#3d6b3d",
    Severity.INFO: "#5a6b7a",
}


@dataclass
class ReportContext:
    """Everything a report renderer is allowed to look at.

    Assembled by the caller from the database before rendering, so the renderer
    itself performs no queries and is therefore trivially testable.
    """

    organization_name: str
    kind: ReportKind
    generated_at: datetime
    findings: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    changes: list[dict[str, Any]] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    scans: list[dict[str, Any]] = field(default_factory=list)
    scope_entries: list[dict[str, Any]] = field(default_factory=list)
    period_start: datetime | None = None
    period_end: datetime | None = None
    title: str | None = None

    # -- Derived summaries -------------------------------------------------

    @property
    def active_findings(self) -> list[dict[str, Any]]:
        active = {s.value for s in ACTIVE_FINDING_STATUSES}
        return [f for f in self.findings if _enum_value(f.get("status")) in active]

    @property
    def by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in SEVERITY_ORDER}
        for finding in self.active_findings:
            key = _enum_value(finding.get("severity"))
            if key in counts:
                counts[key] += 1
        return counts

    @property
    def risk_increasing_changes(self) -> list[dict[str, Any]]:
        return [c for c in self.changes if c.get("is_risk_increasing")]

    def top_findings(self, limit: int = 10) -> list[dict[str, Any]]:
        return sorted(
            self.active_findings,
            key=lambda f: float(f.get("risk_score") or 0.0),
            reverse=True,
        )[:limit]

    def business_critical_findings(self) -> list[dict[str, Any]]:
        return [
            f
            for f in self.active_findings
            if _enum_value(f.get("business_criticality")) == BusinessCriticality.CRITICAL.value
        ]


def _enum_value(value: Any) -> str:
    """Normalise an enum or string to its string value."""
    return value.value if hasattr(value, "value") else str(value or "")


def _fmt(value: Any, default: str = "—") -> str:
    """Render a value for display, never showing ``None`` as a literal."""
    if value is None or value == "":
        return default
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return str(value)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def render_json(context: ReportContext) -> str:
    """Render a machine-readable report.

    The payload is a plain document with no rendering decisions baked in, so a
    consumer can build their own view without parsing prose. Evidence is included
    verbatim, exactly as stored.
    """
    return json.dumps(
        {
            "report": {
                "kind": _enum_value(context.kind),
                "title": context.title or _default_title(context),
                "organization": context.organization_name,
                "generated_at": context.generated_at.isoformat(),
                "period_start": context.period_start.isoformat() if context.period_start else None,
                "period_end": context.period_end.isoformat() if context.period_end else None,
                "generator": "Veyl Continuous Exposure Intelligence",
                "note": (
                    "Every finding below is backed by evidence recorded verbatim from an "
                    "observation. Values labelled USER_PROVIDED were supplied by the "
                    "organization; values labelled OBSERVED were measured by Veyl. "
                    "Attack paths are POTENTIAL unless an authorized check produced "
                    "positive evidence."
                ),
            },
            "summary": {
                "open_findings": len(context.active_findings),
                "by_severity": context.by_severity,
                "asset_count": len(context.assets),
                "reachable_asset_count": sum(
                    1 for a in context.assets if a.get("reachable")
                ),
                "internet_exposed_asset_count": sum(
                    1 for a in context.assets if a.get("internet_exposed")
                ),
                "risk_increasing_changes": len(context.risk_increasing_changes),
                "attack_paths": len(context.attack_paths),
                "scans_included": len(context.scans),
            },
            "findings": context.findings,
            "assets": context.assets,
            "changes": context.changes,
            "attack_paths": context.attack_paths,
            "scans": context.scans,
            "scope_entries": context.scope_entries,
        },
        indent=2,
        sort_keys=False,
        default=str,
    )


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #ffffff; --fg: #1a1f24; --muted: #5a6b7a; --line: #dfe4ea;
  --panel: #f7f9fb; --accent: #1b4b7a;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 40px 28px; background: var(--bg); color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 15px; line-height: 1.55;
}
.wrap { max-width: 980px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 {
  font-size: 18px; margin: 36px 0 12px; padding-bottom: 8px;
  border-bottom: 2px solid var(--line);
}
h3 { font-size: 15px; margin: 20px 0 6px; }
.sub { color: var(--muted); font-size: 13px; margin: 0 0 24px; }
.note {
  background: var(--panel); border-left: 3px solid var(--accent);
  padding: 12px 16px; margin: 16px 0; font-size: 13px; color: #2c3e50;
}
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--panel); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; }
.card {
  flex: 1 1 120px; background: var(--panel); border: 1px solid var(--line);
  border-radius: 6px; padding: 14px;
}
.card .n { font-size: 26px; font-weight: 600; line-height: 1.1; }
.card .l { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-top: 4px; }
.sev { display: inline-block; padding: 2px 8px; border-radius: 3px; color: #fff; font-size: 11px; font-weight: 600; letter-spacing: 0.03em; }
.finding { border: 1px solid var(--line); border-radius: 6px; padding: 16px; margin: 14px 0; }
.finding h3 { margin-top: 0; }
.meta { font-size: 12px; color: var(--muted); margin: 4px 0 10px; }
.field { margin: 10px 0; }
.field .k { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
pre {
  background: #1e2429; color: #e6edf3; padding: 10px 12px; border-radius: 4px;
  overflow-x: auto; font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.evidence { background: var(--panel); border-left: 3px solid var(--muted); padding: 10px 12px; margin: 8px 0; font-size: 13px; }
.footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line); font-size: 12px; color: var(--muted); }
"""


def _sev_badge(severity: Any) -> str:
    key = _enum_value(severity)
    colour = SEVERITY_COLOURS.get(
        Severity(key) if key in {s.value for s in SEVERITY_ORDER} else Severity.INFO,
        "#5a6b7a",
    )
    return f'<span class="sev" style="background:{colour}">{html.escape(key)}</span>'


def _card(number: Any, label: str) -> str:
    return f'<div class="card"><div class="n">{html.escape(str(number))}</div><div class="l">{html.escape(label)}</div></div>'


def _provenance_warning(context: ReportContext) -> str:
    """State plainly which context was asserted rather than measured."""
    asserted = sorted(
        {
            _enum_value(f.get("context_source"))
            for f in context.active_findings
            if _enum_value(f.get("context_source")) == Provenance.USER_PROVIDED.value
        }
    )
    if not asserted:
        return ""
    return (
        '<div class="note"><strong>Mixed provenance.</strong> '
        f"{len(asserted)} finding group(s) in this report are prioritized using business "
        "context your organization provided (marked <code>USER_PROVIDED</code>), not "
        "measured by Veyl. Every technical observation itself is measured.</div>"
    )


def render_html(context: ReportContext) -> str:
    """Render a self-contained HTML report.

    Self-contained on purpose: no external CSS, fonts, or scripts, so the file
    can be attached to an email, opened offline, and still render identically.
    """
    title = html.escape(context.title or _default_title(context))
    severity = context.by_severity
    is_executive = _enum_value(context.kind) == ReportKind.EXECUTIVE.value

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{title}</title>",
        f"<style>{_CSS}</style>",
        "</head><body><div class='wrap'>",
        f"<h1>{title}</h1>",
        (
            f"<p class='sub'>{html.escape(context.organization_name)} &middot; "
            f"generated {_fmt(context.generated_at)}"
            + (
                f" &middot; period {_fmt(context.period_start)} to {_fmt(context.period_end)}"
                if context.period_start or context.period_end
                else ""
            )
            + "</p>"
        ),
        (
            "<div class='note'><strong>How to read this report.</strong> "
            "Findings are backed by evidence recorded verbatim at the time of observation. "
            "Where Veyl could not establish something — for example whether an asset is "
            "reachable from the public internet rather than merely from the scanning "
            "position — the finding says so instead of assuming. Attack paths are "
            "<em>potential</em> unless an authorized check produced positive evidence, and "
            "each one states what was not verified.</div>"
        ),
        _provenance_warning(context),
    ]

    # -- Summary -----------------------------------------------------------
    parts.append("<h2>Summary</h2><div class='cards'>")
    parts.append(_card(len(context.active_findings), "Open findings"))
    parts.append(_card(severity["CRITICAL"], "Critical"))
    parts.append(_card(severity["HIGH"], "High"))
    parts.append(_card(len(context.assets), "Assets"))
    parts.append(
        _card(
            sum(1 for a in context.assets if a.get("internet_exposed")),
            "Registered internet-facing",
        )
    )
    parts.append(_card(len(context.risk_increasing_changes), "Risk-increasing changes"))
    parts.append(_card(len(context.attack_paths), "Potential attack paths"))
    parts.append("</div>")

    parts.append("<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>")
    for sev in SEVERITY_ORDER:
        parts.append(
            f"<tr><td>{_sev_badge(sev)}</td><td>{severity[sev.value]}</td></tr>"
        )
    parts.append("</tbody></table>")

    # -- Priority ----------------------------------------------------------
    top = context.top_findings(10)
    if top:
        parts.append("<h2>Priority</h2>")
        if is_executive:
            parts.append(
                "<p>Ordered by composite risk, which folds business context into technical "
                "severity. A finding appears higher because it matters more to the business, "
                "not because the underlying issue is more severe.</p>"
            )
        parts.append(
            "<table><thead><tr><th>Severity</th><th>Score</th><th>Finding</th>"
            "<th>Asset</th><th>Why it is prioritized</th></tr></thead><tbody>"
        )
        for finding in top:
            parts.append(
                "<tr>"
                f"<td>{_sev_badge(finding.get('severity'))}</td>"
                f"<td>{float(finding.get('risk_score') or 0):.1f}</td>"
                f"<td>{html.escape(str(finding.get('title', '')))}</td>"
                f"<td><code>{html.escape(str(finding.get('asset_key') or finding.get('asset_id', '')))}</code></td>"
                f"<td>{html.escape(str(finding.get('risk_explanation', '')))}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    # -- Changes -----------------------------------------------------------
    if context.changes:
        parts.append("<h2>What changed</h2>")
        increasing = context.risk_increasing_changes
        if increasing:
            parts.append(
                f"<p>{len(increasing)} change(s) since the previous assessment increased exposure.</p>"
            )
        else:
            parts.append("<p>No change since the previous assessment increased exposure.</p>")

        for change in sorted(
            context.changes,
            key=lambda c: (not c.get("is_risk_increasing"), -(float(c.get("risk_score") or 0))),
        ):
            flag = "risk-increasing" if change.get("is_risk_increasing") else "not risk-increasing"
            parts.append("<div class='finding'>")
            parts.append(
                f"<h3>{html.escape(str(change.get('subject', '')))} "
                f"<span class='meta'>({html.escape(_enum_value(change.get('change_type')))}, {flag})</span></h3>"
            )
            parts.append(
                "<div class='field'><div class='k'>Previously</div>"
                f"<pre>{html.escape(_fmt(change.get('previous_state'), '(absent)'))}</pre>"
                "<div class='k'>Now</div>"
                f"<pre>{html.escape(_fmt(change.get('current_state'), '(absent)'))}</pre></div>"
            )
            parts.append(
                f"<div class='field'><div class='k'>Why it matters</div>"
                f"<div>{html.escape(str(change.get('security_significance', '')))}</div></div>"
            )
            parts.append("</div>")

    # -- Attack paths ------------------------------------------------------
    if context.attack_paths:
        parts.append("<h2>Potential attack paths</h2>")
        parts.append(
            "<p>These are <strong>potential</strong> chains inferred from correlated "
            "exposures. Veyl did not attempt exploitation. The limitations of each "
            "correlation are stated below it.</p>"
        )
        for path in sorted(
            context.attack_paths, key=lambda p: -(float(p.get("risk_score") or 0))
        ):
            parts.append("<div class='finding'>")
            parts.append(
                f"<h3>{html.escape(str(path.get('name', '')))} "
                f"<span class='meta'>({html.escape(_enum_value(path.get('state')))}, "
                f"score {float(path.get('risk_score') or 0):.1f})</span></h3>"
            )
            parts.append(f"<p>{html.escape(str(path.get('summary', '')))}</p>")
            if path.get("business_impact"):
                parts.append(
                    f"<div class='field'><div class='k'>Business impact</div>"
                    f"<div>{html.escape(str(path['business_impact']))}</div></div>"
                )
            steps = path.get("steps") or []
            if steps:
                parts.append("<div class='field'><div class='k'>Chain</div><ol>")
                for step in steps:
                    text = step.get("description") if isinstance(step, dict) else str(step)
                    parts.append(f"<li>{html.escape(str(text))}</li>")
                parts.append("</ol></div>")
            if path.get("limitations"):
                parts.append(
                    "<div class='note'><strong>What was not verified.</strong> "
                    f"{html.escape(str(path['limitations']))}</div>"
                )
            parts.append("</div>")

    # -- Findings ----------------------------------------------------------
    parts.append("<h2>Findings</h2>")
    if not context.findings:
        parts.append(
            "<p>No findings recorded for this period. Absence of findings is not proof "
            "of absence of exposure: it reflects what was assessed within authorized scope.</p>"
        )

    for finding in sorted(
        context.findings,
        key=lambda f: (
            -float(f.get("risk_score") or 0),
            _enum_value(f.get("rule_id")),
        ),
    ):
        parts.append("<div class='finding'>")
        parts.append(
            f"<h3>{_sev_badge(finding.get('severity'))} "
            f"{html.escape(str(finding.get('title', '')))}</h3>"
        )
        parts.append(
            "<div class='meta'>"
            f"rule <code>{html.escape(str(finding.get('rule_id', '')))}</code> &middot; "
            f"status {html.escape(_enum_value(finding.get('status')))} &middot; "
            f"confidence {html.escape(_enum_value(finding.get('confidence')))} &middot; "
            f"risk {float(finding.get('risk_score') or 0):.1f} &middot; "
            f"asset <code>{html.escape(str(finding.get('asset_key') or ''))}</code> &middot; "
            f"first seen {_fmt(finding.get('first_seen_at'))}"
            "</div>"
        )

        for key, label in (
            ("description", "What this is"),
            ("impact", "Why it matters"),
            ("detection_explanation", "How Veyl determined this"),
        ):
            if finding.get(key):
                parts.append(
                    f"<div class='field'><div class='k'>{label}</div>"
                    f"<div>{html.escape(str(finding[key]))}</div></div>"
                )

        if finding.get("risk_explanation"):
            parts.append(
                "<div class='field'><div class='k'>Priority rationale</div>"
                f"<div>{html.escape(str(finding['risk_explanation']))}</div></div>"
            )

        # Evidence is the point of the report. Render it verbatim.
        evidence = finding.get("evidence") or []
        if evidence:
            parts.append("<div class='field'><div class='k'>Evidence</div>")
            for item in evidence:
                parts.append(
                    "<div class='evidence'>"
                    f"<div><strong>{html.escape(str(item.get('summary', '')))}</strong></div>"
                    f"<div class='meta'>kind {html.escape(str(item.get('kind', '')))} &middot; "
                    f"matcher <code>{html.escape(str(item.get('matcher', '')))}</code> &middot; "
                    f"provenance {html.escape(_enum_value(item.get('provenance')))} &middot; "
                    f"observed {_fmt(item.get('observed_at'))}</div>"
                    f"<pre>{html.escape(json.dumps(item.get('detail') or {}, indent=2, default=str))}</pre>"
                    f"<div class='meta'>sha256 <code>{html.escape(str(item.get('checksum', ''))[:16])}…</code></div>"
                    "</div>"
                )
            parts.append("</div>")
        else:
            # Should be unreachable: the evaluator refuses matches without
            # evidence. Stated rather than silently omitted, because a finding
            # with no evidence in a report is a defect that should be visible.
            parts.append(
                "<div class='note'>No evidence is attached to this finding. This is a "
                "defect and should be reported: Veyl does not emit findings without "
                "evidence.</div>"
            )

        if finding.get("remediation_summary"):
            parts.append(
                "<div class='field'><div class='k'>Remediation</div>"
                f"<div>{html.escape(str(finding['remediation_summary']))}</div></div>"
            )

        remediation = finding.get("remediation")
        if remediation:
            parts.append(
                "<div class='field'><div class='k'>Tracking</div>"
                f"<div>owner {html.escape(_enum_value(remediation.get('owner')))} &middot; "
                f"priority {html.escape(str(remediation.get('priority', '')))} &middot; "
                f"due {_fmt(remediation.get('due_date'))} &middot; "
                f"{'verified ' + _fmt(remediation.get('verified_at')) if remediation.get('verified_at') else 'not yet verified'}"
                "</div></div>"
            )
        parts.append("</div>")

    # -- Assets ------------------------------------------------------------
    if context.assets:
        parts.append("<h2>Assets in scope of this report</h2>")
        parts.append(
            "<table><thead><tr><th>Asset</th><th>Type</th><th>Environment</th>"
            "<th>Reachable</th><th>Registered internet-facing</th><th>Criticality</th>"
            "<th>Open findings</th></tr></thead><tbody>"
        )
        for asset in sorted(context.assets, key=lambda a: str(a.get("asset_key", ""))):
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(asset.get('asset_key', '')))}</code></td>"
                f"<td>{html.escape(_enum_value(asset.get('asset_type')))}</td>"
                f"<td>{html.escape(_enum_value(asset.get('environment')))}</td>"
                f"<td>{'yes' if asset.get('reachable') else 'no'}</td>"
                f"<td>{'yes' if asset.get('internet_exposed') else 'no'}</td>"
                f"<td>{html.escape(_enum_value(asset.get('business_criticality')))}</td>"
                f"<td>{asset.get('open_finding_count', 0)}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    # -- Scope -------------------------------------------------------------
    if context.scope_entries:
        parts.append("<h2>Authorized scope</h2>")
        parts.append(
            "<p>Veyl assessed only the targets below. A target that is not listed here "
            "was not scanned, and no conclusion should be drawn about it.</p>"
        )
        parts.append(
            "<table><thead><tr><th>Target</th><th>Status</th><th>Authorized by</th>"
            "<th>Expires</th><th>Active</th></tr></thead><tbody>"
        )
        for entry in context.scope_entries:
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(entry.get('domain', '')))}</code></td>"
                f"<td>{html.escape(_enum_value(entry.get('authorization_status')))}</td>"
                f"<td>{html.escape(_fmt(entry.get('authorized_by')))}</td>"
                f"<td>{_fmt(entry.get('expires_at'))}</td>"
                f"<td>{'yes' if entry.get('is_active') else 'no'}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    parts.append(
        "<div class='footer'>"
        f"Generated by Veyl Continuous Exposure Intelligence at {_fmt(context.generated_at)}. "
        "This report reflects what was observed within authorized scope at the times shown. "
        "It is not a guarantee that no other exposure exists."
        "</div>"
    )
    parts.append("</div></body></html>")
    return "\n".join(parts)


def _default_title(context: ReportContext) -> str:
    kind = _enum_value(context.kind)
    label = "Executive exposure report" if kind == ReportKind.EXECUTIVE.value else "Technical findings report"
    return f"{label} — {context.organization_name}"


def render(context: ReportContext, fmt: str) -> str:
    """Render a report in the requested format.

    Raises:
        ValueError: for a format this build cannot render. Refusing is the
            correct behaviour: returning an empty file for an unsupported format
            would look like a successful report.
    """
    normalised = _enum_value(fmt).upper()
    if normalised == "JSON":
        return render_json(context)
    if normalised == "HTML":
        return render_html(context)
    if normalised == "PDF":
        raise ValueError(
            "PDF rendering is not implemented in this build. Generate HTML or JSON "
            "instead, or convert the HTML artifact with a tool such as WeasyPrint. "
            "Veyl does not emit a PDF it cannot render."
        )
    raise ValueError(f"unsupported report format: {fmt!r}")


def generated_at() -> datetime:
    """Single source of the report timestamp, so it is testable."""
    return utcnow()


__all__ = [
    "ReportContext",
    "SEVERITY_ORDER",
    "generated_at",
    "render",
    "render_html",
    "render_json",
]
