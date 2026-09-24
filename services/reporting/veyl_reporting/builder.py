"""Assemble report input from the database, then render and persist it.

The builder is the only part of reporting that touches the database, and it does
so with read-only queries. All tenant filtering happens here, explicitly, on
every query — a report that leaked another organization's evidence would be the
worst possible failure of this product.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from veyl_api.config import settings
from veyl_api.db.base import utcnow
from veyl_api.enums import ACTIVE_FINDING_STATUSES, ReportFormat, ReportKind, ReportStatus
from veyl_api.models import (
    Asset,
    AttackPath,
    Evidence,
    ExposureChange,
    Finding,
    Organization,
    Remediation,
    Report,
    Scan,
    ScopeEntry,
)
from veyl_api.security.sanitize import checksum, safe_join, sanitize_filename

from veyl_reporting.renderers import ReportContext, render

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value or "")


def _finding_dict(
    finding: Finding,
    asset: Asset | None,
    evidence: list[Evidence],
    remediation: Remediation | None,
) -> dict[str, Any]:
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "rule_category": _enum_value(finding.rule_category),
        "title": finding.title,
        "severity": _enum_value(finding.severity),
        "confidence": _enum_value(finding.confidence),
        "status": _enum_value(finding.status),
        "description": finding.description,
        "detection_explanation": finding.detection_explanation,
        "impact": finding.impact,
        "remediation_summary": finding.remediation_summary,
        "references": list(finding.references or []),
        "vulnerability_refs": list(finding.vulnerability_refs or []),
        "risk_score": finding.risk_score,
        "risk_factors": dict(finding.risk_factors or {}),
        "risk_explanation": finding.risk_explanation,
        "criticality_boost": finding.criticality_boost,
        "context_source": _enum_value(asset.context_source) if asset else None,
        "business_criticality": (
            _enum_value(asset.business_criticality) if asset else None
        ),
        "data_classification": (
            _enum_value(asset.data_classification) if asset else None
        ),
        "environment": _enum_value(asset.environment) if asset else None,
        "asset_id": finding.asset_id,
        "asset_key": asset.asset_key if asset else None,
        "first_seen_at": finding.first_seen_at.isoformat(),
        "last_seen_at": finding.last_seen_at.isoformat(),
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "reopen_count": finding.reopen_count,
        "evidence": [
            {
                "id": e.id,
                "kind": e.kind,
                "summary": e.summary,
                # Copied verbatim. Nothing in this pipeline transforms it.
                "detail": dict(e.detail or {}),
                "matcher": e.matcher,
                "provenance": _enum_value(e.provenance),
                "confidence": _enum_value(e.confidence),
                "observed_at": e.observed_at.isoformat(),
                "checksum": e.checksum,
                "observation_id": e.observation_id,
                "scan_id": e.scan_id,
            }
            for e in evidence
        ],
        "remediation": (
            {
                "owner": _enum_value(remediation.owner),
                "priority": remediation.priority,
                "due_date": remediation.due_date.isoformat() if remediation.due_date else None,
                "notes": remediation.notes,
                "verified_at": (
                    remediation.verified_at.isoformat() if remediation.verified_at else None
                ),
            }
            if remediation
            else None
        ),
    }


def build_context(
    session: Session,
    *,
    organization_id: str,
    kind: ReportKind,
    scan_id: str | None = None,
    period_start: datetime | None = None,
    period_end: datetime | None = None,
    title: str | None = None,
) -> ReportContext:
    """Gather report input for one organization.

    When ``scan_id`` is given the report covers that scan; otherwise it covers
    all currently active findings. Either way the query is filtered by
    ``organization_id`` at the database, not in Python.
    """
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError(f"organization {organization_id} not found")

    # -- Findings ----------------------------------------------------------
    finding_query = (
        select(Finding)
        .where(Finding.organization_id == organization_id)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.remediation),
        )
    )
    if scan_id:
        finding_query = finding_query.where(Finding.last_scan_id == scan_id)
    if period_start:
        finding_query = finding_query.where(Finding.last_seen_at >= period_start)
    if period_end:
        finding_query = finding_query.where(Finding.last_seen_at <= period_end)

    findings = list(session.execute(finding_query).scalars())

    asset_ids = {f.asset_id for f in findings}
    assets_by_id = (
        {
            a.id: a
            for a in session.execute(select(Asset).where(Asset.id.in_(asset_ids))).scalars()
        }
        if asset_ids
        else {}
    )

    finding_dicts = [
        _finding_dict(f, assets_by_id.get(f.asset_id), list(f.evidence), f.remediation)
        for f in findings
    ]

    # -- Assets ------------------------------------------------------------
    asset_query = select(Asset).where(Asset.organization_id == organization_id)
    if scan_id:
        # Only assets touched by this scan, so a scan-scoped report stays scoped.
        touched = {
            f.asset_id for f in findings
        }
        assets = list(
            session.execute(asset_query.where(Asset.id.in_(touched))).scalars()
        ) if touched else []
    else:
        assets = list(session.execute(asset_query).scalars())

    open_counts: dict[str, int] = {}
    if assets:
        rows = session.execute(
            select(Finding.asset_id, func.count())
            .where(
                Finding.organization_id == organization_id,
                Finding.asset_id.in_([a.id for a in assets]),
                Finding.status.in_(sorted(ACTIVE_FINDING_STATUSES, key=lambda s: s.value)),
            )
            .group_by(Finding.asset_id)
        ).all()
        open_counts = dict(rows)

    asset_dicts = [
        {
            "id": a.id,
            "asset_key": a.asset_key,
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "asset_type": _enum_value(a.asset_type),
            "environment": _enum_value(a.environment),
            "status": _enum_value(a.status),
            "reachable": a.reachable,
            "internet_exposed": a.internet_exposed,
            "business_criticality": _enum_value(a.business_criticality),
            "data_classification": _enum_value(a.data_classification),
            "business_function": _enum_value(a.business_function),
            "owner": _enum_value(a.owner),
            "context_source": _enum_value(a.context_source),
            "first_seen": a.first_seen.isoformat(),
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "open_finding_count": open_counts.get(a.id, 0),
        }
        for a in assets
    ]

    # -- Changes -----------------------------------------------------------
    change_query = select(ExposureChange).where(
        ExposureChange.organization_id == organization_id
    )
    if scan_id:
        change_query = change_query.where(ExposureChange.scan_id == scan_id)
    if period_start:
        change_query = change_query.where(ExposureChange.detected_at >= period_start)
    if period_end:
        change_query = change_query.where(ExposureChange.detected_at <= period_end)

    changes = list(
        session.execute(
            change_query.order_by(ExposureChange.detected_at.desc()).limit(500)
        ).scalars()
    )
    change_dicts = [
        {
            "id": c.id,
            "change_type": _enum_value(c.change_type),
            "significance": _enum_value(c.significance),
            "subject": c.subject,
            "previous_state": c.previous_state,
            "current_state": c.current_state,
            "evidence": dict(c.evidence or {}),
            "security_significance": c.security_significance,
            "is_risk_increasing": c.is_risk_increasing,
            "risk_score": c.risk_score,
            "acknowledged": c.acknowledged,
            "detected_at": c.detected_at.isoformat(),
        }
        for c in changes
    ]

    # -- Attack paths ------------------------------------------------------
    paths = list(
        session.execute(
            select(AttackPath)
            .where(
                AttackPath.organization_id == organization_id,
                AttackPath.is_active.is_(True),
            )
            .order_by(AttackPath.risk_score.desc())
            .limit(50)
        ).scalars()
    )
    path_dicts = [
        {
            "id": p.id,
            "name": p.name,
            "summary": p.summary,
            "state": _enum_value(p.state),
            "confidence": _enum_value(p.confidence),
            "risk_score": p.risk_score,
            "steps": list(p.steps or []),
            "finding_ids": list(p.finding_ids or []),
            "asset_ids": list(p.asset_ids or []),
            "business_impact": p.business_impact,
            "limitations": p.limitations,
            "detected_at": p.detected_at.isoformat(),
        }
        for p in paths
    ]

    # -- Scans -------------------------------------------------------------
    scan_query = select(Scan).where(Scan.organization_id == organization_id)
    if scan_id:
        scan_query = scan_query.where(Scan.id == scan_id)
    scans = list(
        session.execute(scan_query.order_by(Scan.started_at.desc()).limit(25)).scalars()
    )
    scan_dicts = [
        {
            "id": s.id,
            "status": _enum_value(s.status),
            "label": s.label,
            "started_at": s.started_at.isoformat(),
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "targets_requested": s.targets_requested,
            "targets_scanned": s.targets_scanned,
            "targets_blocked": s.targets_blocked,
            "assets_found": s.assets_found,
            "findings_created": s.findings_created,
            "changes_detected": s.changes_detected,
            "blocked_targets": list(s.blocked_targets or []),
        }
        for s in scans
    ]

    # -- Scope -------------------------------------------------------------
    scope_entries = list(
        session.execute(
            select(ScopeEntry).where(ScopeEntry.organization_id == organization_id)
        ).scalars()
    )
    scope_dicts = [
        {
            "id": e.id,
            "domain": e.domain,
            "cidr": e.cidr,
            "authorization_status": _enum_value(e.authorization_status),
            "authorized_by": e.authorized_by,
            "authorized_at": e.authorized_at.isoformat() if e.authorized_at else None,
            "expires_at": e.expires_at.isoformat() if e.expires_at else None,
            "is_active": e.is_active,
        }
        for e in scope_entries
    ]

    return ReportContext(
        organization_name=organization.name,
        kind=kind,
        generated_at=utcnow(),
        findings=finding_dicts,
        assets=asset_dicts,
        changes=change_dicts,
        attack_paths=path_dicts,
        scans=scan_dicts,
        scope_entries=scope_dicts,
        period_start=period_start,
        period_end=period_end,
        title=title,
    )


def generate_report(
    session: Session,
    *,
    organization_id: str,
    kind: ReportKind,
    fmt: ReportFormat,
    user_id: str | None = None,
    scan_id: str | None = None,
    title: str | None = None,
    period_start: datetime | None = None,
    period_end: datetime | None = None,
    persist: bool = True,
) -> Report:
    """Generate a report and, optionally, persist it with its artifact.

    On any render failure the report row is still created with status FAILED and
    the error recorded. A failed report that leaves no trace is worse than one
    that fails loudly, because the user cannot tell "nothing generated" from
    "generation is broken".
    """
    record = Report(
        organization_id=organization_id,
        kind=kind,
        fmt=fmt,
        status=ReportStatus.PENDING,
        title=title or _default_title(kind),
        scan_id=scan_id,
        generated_by_user_id=user_id,
        period_start=period_start,
        period_end=period_end,
    )
    if persist:
        session.add(record)
        session.flush()

    try:
        context = build_context(
            session,
            organization_id=organization_id,
            kind=kind,
            scan_id=scan_id,
            period_start=period_start,
            period_end=period_end,
            title=title,
        )
        body = render(context, fmt)
        artifact_path = _write_artifact(
            organization_id=organization_id,
            kind=kind,
            fmt=fmt,
            report_id=record.id if record.id else None,
            body=body,
        )
    except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
        record.status = ReportStatus.FAILED
        record.error_message = f"{type(exc).__name__}: {exc}"
        if persist:
            session.flush()
        return record

    record.status = ReportStatus.READY
    record.artifact_path = artifact_path
    record.checksum = checksum(body)
    record.error_message = None
    if persist:
        session.flush()
    return record


def _default_title(kind: ReportKind) -> str:
    label = (
        "Executive exposure report"
        if _enum_value(kind) == ReportKind.EXECUTIVE.value
        else "Technical findings report"
    )
    return label


def _write_artifact(
    *,
    organization_id: str,
    kind: ReportKind,
    fmt: ReportFormat,
    report_id: str | None,
    body: str,
) -> str:
    """Write the report under the artifact directory and return a relative path.

    Every path component is generated by this function; no user input reaches the
    filesystem. ``safe_join`` is still used as a belt-and-braces check, so a future
    change that does thread a name through cannot escape the artifact root.
    """
    extension = {"JSON": "json", "HTML": "html", "PDF": "pdf"}.get(
        _enum_value(fmt), "txt"
    )
    base = Path(settings.artifact_dir).resolve()
    filename = sanitize_filename(
        f"{_enum_value(kind).lower()}-{report_id or utcnow().strftime('%Y%m%d%H%M%S')}.{extension}"
    )
    relative = Path(organization_id) / filename
    target = safe_join(str(base), str(relative))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return str(relative).replace("\\", "/")


__all__ = ["build_context", "generate_report"]
