"""Audit log endpoints.

The audit log is tamper-evident: each entry chains to the previous one for the
same organization, and ``GET /audit/verify`` walks the chain and reports the
first broken link. This is what makes the log worth reading — a claim of
integrity that is not checkable is not a claim, it is a slogan.
"""

from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from veyl_api.api.deps import DbSession, require
from veyl_api.api.schemas import AuditEntryOut, AuditVerificationOut, Page
from veyl_api.audit import verify_chain
from veyl_api.models import AuditLog

router = APIRouter()


def _entry_out(entry: AuditLog) -> AuditEntryOut:
    return AuditEntryOut(
        id=entry.id,
        action=entry.action.value if hasattr(entry.action, "value") else str(entry.action),
        actor_email=entry.actor_email,
        actor_user_id=entry.actor_user_id,
        actor_role=entry.actor_role,
        resource_type=entry.resource_type,
        resource_id=entry.resource_id,
        result=entry.result,
        detail=entry.detail,
        metadata=dict(entry.metadata_json or {}),
        ip_address=entry.ip_address,
        created_at=entry.created_at,
        prev_hash=entry.prev_hash,
        entry_hash=entry.entry_hash,
    )


@router.get("", response_model=Page, summary="List audit entries")
def list_audit(
    session: DbSession,
    context=require("audit:read"),
    action: str | None = None,
    result: str | None = None,
    actor_user_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0),
) -> Page:
    """List audit entries, newest first."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    conditions = [AuditLog.organization_id == context.organization.id]
    if action:
        conditions.append(AuditLog.action == action)
    if result:
        conditions.append(AuditLog.result == result)
    if actor_user_id:
        conditions.append(AuditLog.actor_user_id == actor_user_id)

    total = session.execute(
        select(func.count()).select_from(AuditLog).where(*conditions)
    ).scalar_one()

    stmt = (
        select(AuditLog)
        .where(*conditions)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = list(session.execute(stmt).scalars())
    return Page(total=total, limit=limit, offset=offset, items=[_entry_out(e) for e in rows])


@router.get(
    "/verify",
    response_model=AuditVerificationOut,
    summary="Verify the integrity of this organization's audit chain",
)
def verify(session: DbSession, context=require("audit:read")) -> AuditVerificationOut:
    """Walk the hash chain and report whether it is intact.

    On failure, ``first_bad_entry_id`` identifies the entry where the chain
    breaks, which is what an investigator needs. A bare "invalid" would be
    useless because it does not say where to start looking.
    """
    result = verify_chain(session, context.organization.id)
    return AuditVerificationOut(
        organization_id=result.organization_id,
        entries_checked=result.entries_checked,
        is_valid=result.is_valid,
        first_bad_entry_id=result.first_bad_entry_id,
        reason=result.reason,
        checked_at=result.checked_at,
    )


@router.get("/summary", response_model=dict, summary="Summarise audit activity")
def summary(session: DbSession, context=require("audit:read")) -> dict:
    """Count entries by action and outcome for a quick overview."""
    by_action = dict(
        session.execute(
            select(AuditLog.action, func.count())
            .where(AuditLog.organization_id == context.organization.id)
            .group_by(AuditLog.action)
        ).all()
    )
    by_result = dict(
        session.execute(
            select(AuditLog.result, func.count())
            .where(AuditLog.organization_id == context.organization.id)
            .group_by(AuditLog.result)
        ).all()
    )
    total = sum(by_action.values())
    actors = session.execute(
        select(func.count(func.distinct(AuditLog.actor_user_id))).where(
            AuditLog.organization_id == context.organization.id,
            AuditLog.actor_user_id.is_not(None),
        )
    ).scalar_one()

    return {
        "total": total,
        "by_action": {
            (k.value if hasattr(k, "value") else str(k)): v for k, v in by_action.items()
        },
        "by_result": by_result,
        "distinct_actors": actors,
    }
