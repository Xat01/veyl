"""Exposure change endpoints.

A change list answers "what moved since last time". The response always carries
``is_risk_increasing`` alongside the raw before/after values, because the same
change type can go either way — losing a security header is a regression, gaining
one is not, and a UI that cannot tell them apart will cry wolf until users stop
reading it.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from veyl_api.api.deps import DbSession, require
from veyl_api.api.schemas import ChangeAcknowledge, ExposureChangeOut, Page
from veyl_api.audit import AuditRecord, write_audit
from veyl_api.enums import AuditAction
from veyl_api.models import ExposureChange

router = APIRouter()


def _change_out(change: ExposureChange) -> ExposureChangeOut:
    return ExposureChangeOut(
        id=change.id,
        scan_id=change.scan_id,
        previous_scan_id=change.previous_scan_id,
        asset_id=change.asset_id,
        change_type=change.change_type,
        significance=change.significance,
        subject=change.subject,
        previous_state=change.previous_state,
        current_state=change.current_state,
        evidence=dict(change.evidence or {}),
        security_significance=change.security_significance,
        is_risk_increasing=change.is_risk_increasing,
        risk_score=change.risk_score,
        asset_criticality=change.asset_criticality,
        asset_environment=change.asset_environment,
        business_function=change.business_function,
        acknowledged=change.acknowledged,
        detected_at=change.detected_at,
    )


@router.get("", response_model=Page, summary="List exposure changes")
def list_changes(
    session: DbSession,
    context=require("graph:read"),
    scan_id: str | None = None,
    asset_id: str | None = None,
    change_type: str | None = None,
    risk_increasing_only: bool = False,
    include_acknowledged: bool = True,
    limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0),
) -> Page:
    """List changes, newest first, with risk-increasing ones filterable."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    conditions = [ExposureChange.organization_id == context.organization.id]
    if scan_id:
        conditions.append(ExposureChange.scan_id == scan_id)
    if asset_id:
        conditions.append(ExposureChange.asset_id == asset_id)
    if change_type:
        conditions.append(ExposureChange.change_type == change_type)
    if risk_increasing_only:
        conditions.append(ExposureChange.is_risk_increasing.is_(True))
    if not include_acknowledged:
        conditions.append(ExposureChange.acknowledged.is_(False))

    total = session.execute(
        select(func.count()).select_from(ExposureChange).where(*conditions)
    ).scalar_one()

    stmt = (
        select(ExposureChange)
        .where(*conditions)
        .order_by(
            ExposureChange.is_risk_increasing.desc(),
            ExposureChange.detected_at.desc(),
        )
        .limit(limit)
        .offset(offset)
    )
    rows = list(session.execute(stmt).scalars())
    return Page(total=total, limit=limit, offset=offset, items=[_change_out(c) for c in rows])


@router.get("/{change_id}", response_model=ExposureChangeOut, summary="Fetch one change")
def get_change(
    change_id: str, session: DbSession, context=require("graph:read")
) -> ExposureChangeOut:
    change = session.get(ExposureChange, change_id)
    if change is None or change.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="change not found")
    return _change_out(change)


@router.patch(
    "/{change_id}",
    response_model=ExposureChangeOut,
    summary="Acknowledge or unacknowledge a change",
)
def acknowledge_change(
    change_id: str,
    payload: ChangeAcknowledge,
    session: DbSession,
    context=require("graph:read"),
) -> ExposureChangeOut:
    """Mark a change as seen.

    Acknowledging records that a human looked at it. It does not change the
    change's severity, and it does not mark anything as remediated — those are
    different claims.
    """
    change = session.get(ExposureChange, change_id)
    if change is None or change.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="change not found")

    if change.acknowledged != payload.acknowledged:
        change.acknowledged = payload.acknowledged
        write_audit(
            session,
            AuditRecord(
                action=AuditAction.CHANGE_ACKNOWLEDGED,
                organization_id=context.organization.id,
                actor_user_id=context.user.id,
                actor_email=context.user.email,
                actor_role=context.role.value,
                resource_type="exposure_change",
                resource_id=change.id,
                detail=(
                    f"{change.subject}: acknowledged={payload.acknowledged}"
                ),
            ),
        )
        session.commit()
        session.refresh(change)
    return _change_out(change)
