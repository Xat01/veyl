"""Attack path endpoints.

The language here is load-bearing. A path is ``POTENTIAL`` unless an authorized
non-destructive check produced positive evidence, and every response carries a
``limitations`` string stating what Veyl did not verify. An API that returned
"attack path" without that caveat would invite users to over-read the finding,
and the whole product's credibility rests on not doing that.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from veyl_api.api.deps import DbSession, require
from veyl_api.api.schemas import AttackPathOut, Page
from veyl_api.audit import AuditRecord, write_audit
from veyl_api.enums import AuditAction
from veyl_api.models import AttackPath

router = APIRouter()


def _path_out(path: AttackPath) -> AttackPathOut:
    return AttackPathOut(
        id=path.id,
        name=path.name,
        summary=path.summary,
        state=path.state,
        confidence=path.confidence,
        risk_score=path.risk_score,
        node_keys=list(path.node_keys or []),
        steps=list(path.steps or []),
        finding_ids=list(path.finding_ids or []),
        asset_ids=list(path.asset_ids or []),
        business_impact=path.business_impact,
        limitations=path.limitations,
        is_active=path.is_active,
        detected_at=path.detected_at,
    )


@router.get("", response_model=Page, summary="List attack paths")
def list_paths(
    session: DbSession,
    context=require("graph:read"),
    active_only: bool = True,
    state: str | None = None,
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
) -> Page:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    conditions = [AttackPath.organization_id == context.organization.id]
    if active_only:
        conditions.append(AttackPath.is_active.is_(True))
    if state:
        conditions.append(AttackPath.state == state)

    total = session.execute(
        select(func.count()).select_from(AttackPath).where(*conditions)
    ).scalar_one()

    stmt = (
        select(AttackPath)
        .where(*conditions)
        .order_by(AttackPath.risk_score.desc(), AttackPath.detected_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = list(session.execute(stmt).scalars())
    return Page(total=total, limit=limit, offset=offset, items=[_path_out(p) for p in rows])


@router.get("/{path_id}", response_model=AttackPathOut, summary="Fetch one attack path")
def get_path(path_id: str, session: DbSession, context=require("graph:read")) -> AttackPathOut:
    path = session.get(AttackPath, path_id)
    if path is None or path.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="attack path not found")
    return _path_out(path)


@router.post(
    "/recompute", response_model=dict, summary="Recompute attack paths from the current graph"
)
def recompute_paths(session: DbSession, context=require("asset:write")) -> dict:
    """Re-derive correlated paths from current findings.

    ``correlate_attack_paths`` replaces this tenant's paths as a unit, so a chain
    that no longer exists stops being reported. Anything Veyl can no longer
    support with evidence should disappear, not linger.
    """
    from veyl_correlation import correlate_attack_paths, rebuild_graph

    rebuild_graph(session, organization_id=context.organization.id)
    paths = correlate_attack_paths(session, organization_id=context.organization.id)

    write_audit(
        session,
        AuditRecord(
            action=AuditAction.ATTACK_PATHS_RECOMPUTED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="organization",
            resource_id=context.organization.id,
            detail=f"{len(paths)} potential path(s) recomputed",
        ),
    )
    session.commit()
    return {
        "attack_paths": len(paths),
        "note": (
            "All paths are POTENTIAL unless an authorized check produced positive "
            "evidence. Each path carries its own limitations statement."
        ),
    }
