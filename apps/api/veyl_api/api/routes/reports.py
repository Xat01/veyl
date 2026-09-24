"""Report generation and download.

Generating and downloading are separate endpoints on purpose: generation is a
write (it records an audit event and writes an artifact), while download is a
read of a file that already exists. Splitting them means a report can be
generated once and fetched repeatedly without re-running the renderer or
duplicating the audit trail.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from sqlalchemy import func, select

from veyl_api.api.deps import DbSession, require
from veyl_api.api.schemas import Page, ReportOut, ReportRequest
from veyl_api.audit import AuditRecord, write_audit
from veyl_api.config import settings
from veyl_api.enums import AuditAction, ReportFormat, ReportStatus
from veyl_api.models import Report
from veyl_api.security.sanitize import safe_join

router = APIRouter()

_ALLOWED_PREFIXES = ("EXECUTIVE", "TECHNICAL")


def _report_out(record: Report) -> ReportOut:
    return ReportOut(
        id=record.id,
        kind=record.kind,
        fmt=record.fmt,
        status=record.status,
        title=record.title,
        scan_id=record.scan_id,
        checksum=record.checksum,
        error_message=record.error_message,
        period_start=record.period_start,
        period_end=record.period_end,
        created_at=record.created_at,
        download_url=(
            f"/reports/{record.id}/download"
            if record.status == ReportStatus.READY and record.artifact_path
            else None
        ),
    )


@router.get("", response_model=Page, summary="List generated reports")
def list_reports(
    session: DbSession,
    context=require("report:read"),
    kind: str | None = None,
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
) -> Page:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    conditions = [Report.organization_id == context.organization.id]
    if kind:
        conditions.append(Report.kind == kind)

    total = session.execute(
        select(func.count()).select_from(Report).where(*conditions)
    ).scalar_one()

    rows = list(
        session.execute(
            select(Report)
            .where(*conditions)
            .order_by(Report.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
    )
    return Page(total=total, limit=limit, offset=offset, items=[_report_out(r) for r in rows])


@router.post(
    "",
    response_model=ReportOut,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a report",
)
def create_report(
    payload: ReportRequest, session: DbSession, context=require("report:generate")
) -> ReportOut:
    """Render a report and record it.

    PDF is refused with an explicit reason rather than silently producing HTML
    or an empty file. The product does not ship a feature it cannot honour.
    """
    if payload.fmt == ReportFormat.PDF:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "PDF rendering is not implemented in this build. Generate HTML and "
                "convert it, or request JSON."
            ),
        )

    from veyl_reporting import generate_report

    record = generate_report(
        session,
        organization_id=context.organization.id,
        kind=payload.kind,
        fmt=payload.fmt,
        user_id=context.user.id,
        scan_id=payload.scan_id,
        title=payload.title,
        period_start=payload.period_start,
        period_end=payload.period_end,
    )

    write_audit(
        session,
        AuditRecord(
            action=AuditAction.REPORT_GENERATED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="report",
            resource_id=record.id,
            result="SUCCESS" if record.status == ReportStatus.READY else "FAILURE",
            detail=(
                f"{payload.kind.value}/{payload.fmt.value}: {record.status.value}"
                + (f" ({record.error_message})" if record.error_message else "")
            ),
        ),
    )
    session.commit()
    session.refresh(record)
    return _report_out(record)


@router.get("/{report_id}", response_model=ReportOut, summary="Fetch report metadata")
def get_report(report_id: str, session: DbSession, context=require("report:read")) -> ReportOut:
    record = session.get(Report, report_id)
    if record is None or record.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    return _report_out(record)


@router.get(
    "/{report_id}/download",
    summary="Download a generated report",
    # Returns a Response subclass, not a serialised model, so FastAPI must not
    # try to derive a response schema from the annotation.
    response_model=None,
)
def download_report(
    report_id: str, session: DbSession, context=require("report:read")
) -> Response:
    """Return the rendered artifact.

    The path is re-resolved and confined to the artifact root at read time as
    well as write time: a stored path is not trusted simply because this process
    wrote it.
    """
    record = session.get(Report, report_id)
    if record is None or record.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")

    if record.status != ReportStatus.READY or not record.artifact_path:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"report is {record.status.value} and has no artifact"
                + (f": {record.error_message}" if record.error_message else "")
            ),
        )

    root = Path(settings.artifact_dir).resolve()
    try:
        path = safe_join(str(root), record.artifact_path)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="stored artifact path is invalid",
        ) from exc

    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=(
                "the artifact file for this report is no longer present on disk; "
                "regenerate the report"
            ),
        )

    body = path.read_text(encoding="utf-8")
    filename = path.name

    fmt = record.fmt
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        # The checksum lets a downloader verify they received the artifact that
        # was generated, not a modified copy.
        "X-Content-Checksum": record.checksum or "",
    }

    if fmt == ReportFormat.HTML:
        return HTMLResponse(content=body, headers=headers)
    if fmt == ReportFormat.JSON:
        return JSONResponse(content=_loads(body), headers=headers)
    return PlainTextResponse(content=body, headers=headers)


def _loads(body: str):
    """Parse a stored JSON artifact; on failure return it as text.

    Returning the raw body rather than raising means a corrupted artifact is
    still downloadable and diagnosable instead of becoming an opaque 500.
    """
    import json

    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"error": "stored artifact is not valid JSON", "raw": body[:10000]}
