"""Finding endpoints: the evidence trail, the risk rationale, and remediation.

Every response here is built to answer the question a user actually has:
"why should I believe this, and what do I do about it". A finding with no
evidence and no detection explanation is a bug in the product, so the response
schema makes both fields required rather than optional.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from veyl_api.api.deps import DbSession, require
from veyl_api.api.schemas import (
    EvidenceOut,
    FindingDetail,
    FindingEventOut,
    FindingStatusUpdate,
    FindingSummary,
    Page,
    RemediationOut,
    RemediationUpdate,
)
from veyl_api.audit import AuditRecord, write_audit
from veyl_api.db.base import utcnow
from veyl_api.enums import ACTIVE_FINDING_STATUSES, AuditAction, FindingStatus, Severity
from veyl_api.models import Asset, Evidence, Finding, FindingEvent, Remediation

router = APIRouter()

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

#: Statuses that mean the condition is still live. Sourced from the enum module
#: so the API, the scanner and the correlation engine cannot disagree about what
#: "still needs attention" means.
_ACTIVE_STATUSES = sorted(ACTIVE_FINDING_STATUSES, key=lambda s: s.value)


def _evidence_out(evidence: Evidence) -> EvidenceOut:
    return EvidenceOut(
        id=evidence.id,
        kind=evidence.kind,
        summary=evidence.summary,
        detail=dict(evidence.detail or {}),
        matcher=evidence.matcher,
        provenance=evidence.provenance,
        confidence=evidence.confidence,
        observed_at=evidence.observed_at,
        checksum=evidence.checksum,
        observation_id=evidence.observation_id,
        scan_id=evidence.scan_id,
    )


def _remediation_out(record: Remediation) -> RemediationOut:
    return RemediationOut(
        id=record.id,
        owner=record.owner,
        assignee_user_id=record.assignee_user_id,
        priority=record.priority,
        due_date=record.due_date,
        notes=record.notes,
        verified_at=record.verified_at,
        verified_by_scan_id=record.verified_by_scan_id,
        verification_evidence=(
            dict(record.verification_evidence) if record.verification_evidence else None
        ),
        updated_at=record.updated_at,
    )


def _event_out(event: FindingEvent) -> FindingEventOut:
    return FindingEventOut(
        id=event.id,
        event_type=event.event_type,
        from_value=event.from_value,
        to_value=event.to_value,
        detail=event.detail,
        actor_label=event.actor_label,
        created_at=event.created_at,
    )


def _finding_summary(
    finding: Finding, asset: Asset | None, evidence_count: int = 0, has_remediation: bool = False
) -> FindingSummary:
    return FindingSummary(
        id=finding.id,
        dedup_key=finding.dedup_key,
        rule_id=finding.rule_id,
        rule_category=finding.rule_category.value,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        status=finding.status,
        risk_score=finding.risk_score,
        criticality_boost=finding.criticality_boost,
        asset_id=finding.asset_id,
        asset_key=asset.asset_key if asset else None,
        asset_hostname=asset.hostname if asset else None,
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        resolved_at=finding.resolved_at,
        reopen_count=finding.reopen_count,
        has_remediation=has_remediation,
        evidence_count=evidence_count,
    )


@router.get("", response_model=Page, summary="List findings")
def list_findings(
    session: DbSession,
    context=require("finding:read"),
    severity: str | None = None,
    status_filter: str | None = None,
    rule_id: str | None = None,
    asset_id: str | None = None,
    category: str | None = None,
    active_only: bool = True,
    search: str | None = None,
    sort: str = "risk",
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
) -> Page:
    """List findings, ordered by risk by default.

    Sorting by risk rather than severity is deliberate: severity is intrinsic to
    the rule, while the score folds in business context. Sorting by severity
    alone would put a medium finding on an unclassified test host above a high
    finding on the payment API.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    conditions = [Finding.organization_id == context.organization.id]
    if severity:
        conditions.append(Finding.severity == severity)
    if status_filter:
        conditions.append(Finding.status == status_filter)
    elif active_only:
        conditions.append(Finding.status.in_(_ACTIVE_STATUSES))
    if rule_id:
        conditions.append(Finding.rule_id == rule_id)
    if asset_id:
        conditions.append(Finding.asset_id == asset_id)
    if category:
        conditions.append(Finding.rule_category == category)
    if search:
        pattern = f"%{search.strip().lower()}%"
        conditions.append(
            or_(
                func.lower(Finding.title).like(pattern),
                func.lower(Finding.description).like(pattern),
                func.lower(Finding.rule_id).like(pattern),
            )
        )

    total = session.execute(
        select(func.count()).select_from(Finding).where(*conditions)
    ).scalar_one()

    order = {
        "risk": (Finding.risk_score.desc(), Finding.last_seen_at.desc()),
        "severity": (Finding.severity.asc(), Finding.risk_score.desc()),
        "recent": (Finding.last_seen_at.desc(), Finding.risk_score.desc()),
        "oldest": (Finding.first_seen_at.asc(), Finding.risk_score.desc()),
    }.get(sort, (Finding.risk_score.desc(), Finding.last_seen_at.desc()))

    stmt = select(Finding).where(*conditions).order_by(*order).limit(limit).offset(offset)
    rows = list(session.execute(stmt).scalars())

    asset_ids = {f.asset_id for f in rows}
    assets = {
        a.id: a
        for a in session.execute(select(Asset).where(Asset.id.in_(asset_ids))).scalars()
    } if asset_ids else {}

    finding_ids = [f.id for f in rows]
    remediation_ids = (
        set(
            session.execute(
                select(Remediation.finding_id).where(Remediation.finding_id.in_(finding_ids))
            ).scalars()
        )
        if finding_ids
        else set()
    )
    evidence_counts = (
        dict(
            session.execute(
                select(Evidence.finding_id, func.count())
                .where(Evidence.finding_id.in_(finding_ids))
                .group_by(Evidence.finding_id)
            ).all()
        )
        if finding_ids
        else {}
    )

    return Page(
        total=total,
        limit=limit,
        offset=offset,
        items=[
            _finding_summary(
                f,
                assets.get(f.asset_id),
                evidence_counts.get(f.id, 0),
                f.id in remediation_ids,
            )
            for f in rows
        ],
    )


@router.get("/{finding_id}", response_model=FindingDetail, summary="Fetch a finding in full")
def get_finding(
    finding_id: str, session: DbSession, context=require("finding:read")
) -> FindingDetail:
    """Return the finding with its evidence, rationale, and history.

    This is the endpoint that carries the product's core claim, so it returns
    everything needed to audit the conclusion without a second request.
    """
    stmt = (
        select(Finding)
        .where(Finding.id == finding_id, Finding.organization_id == context.organization.id)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.remediation),
            selectinload(Finding.history),
        )
    )
    finding = session.execute(stmt).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    asset = session.get(Asset, finding.asset_id)
    base = _finding_summary(
        finding,
        asset,
        len(finding.evidence),
        finding.remediation is not None,
    )

    return FindingDetail(
        **base.model_dump(),
        description=finding.description,
        detection_explanation=finding.detection_explanation,
        impact=finding.impact,
        remediation_summary=finding.remediation_summary,
        references=list(finding.references or []),
        vulnerability_refs=list(finding.vulnerability_refs or []),
        risk_factors=dict(finding.risk_factors or {}),
        risk_explanation=finding.risk_explanation,
        evidence=[_evidence_out(e) for e in finding.evidence],
        remediation=_remediation_out(finding.remediation) if finding.remediation else None,
        history=[_event_out(e) for e in sorted(finding.history, key=lambda e: e.created_at)],
    )


@router.patch(
    "/{finding_id}/status", response_model=FindingSummary, summary="Change a finding's status"
)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    session: DbSession,
    context=require("finding:write"),
) -> FindingSummary:
    """Move a finding between OPEN, ACKNOWLEDGED, RESOLVED, and so on.

    A status change is always recorded as a FindingEvent, so the finding carries
    its own history rather than relying on the org-wide audit log alone.
    """
    finding = session.get(Finding, finding_id)
    if finding is None or finding.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    previous = finding.status
    if payload.status == previous:
        return _finding_summary(finding, session.get(Asset, finding.asset_id))

    finding.status = payload.status
    if payload.status == FindingStatus.RESOLVED:
        finding.resolved_at = utcnow()
    elif previous == FindingStatus.RESOLVED:
        # Reopening clears the resolution timestamp. Counting the reopen gives
        # visibility into findings that keep coming back.
        finding.resolved_at = None
        finding.reopen_count += 1

    session.add(
        FindingEvent(
            organization_id=context.organization.id,
            finding_id=finding.id,
            event_type="STATUS_CHANGED",
            from_value=previous.value,
            to_value=payload.status.value,
            detail=payload.note,
            actor_user_id=context.user.id,
            actor_label=context.user.email,
            created_at=utcnow(),
        )
    )
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.FINDING_STATUS_CHANGED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="finding",
            resource_id=finding.id,
            detail=f"{previous.value} -> {payload.status.value}"
            + (f": {payload.note}" if payload.note else ""),
        ),
    )
    session.commit()
    session.refresh(finding)
    return _finding_summary(
        finding,
        session.get(Asset, finding.asset_id),
        len(finding.evidence),
        finding.remediation is not None,
    )


@router.get(
    "/{finding_id}/evidence",
    response_model=list[EvidenceOut],
    summary="List a finding's evidence",
)
def list_evidence(
    finding_id: str, session: DbSession, context=require("finding:read")
) -> list[EvidenceOut]:
    finding = session.get(Finding, finding_id)
    if finding is None or finding.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return [
        _evidence_out(e)
        for e in sorted(finding.evidence, key=lambda e: e.observed_at)
    ]


@router.get(
    "/{finding_id}/history",
    response_model=list[FindingEventOut],
    summary="List a finding's event history",
)
def list_history(
    finding_id: str, session: DbSession, context=require("finding:read")
) -> list[FindingEventOut]:
    finding = session.get(Finding, finding_id)
    if finding is None or finding.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return [
        _event_out(e) for e in sorted(finding.history, key=lambda e: e.created_at)
    ]


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


@router.put(
    "/{finding_id}/remediation",
    response_model=RemediationOut,
    summary="Create or update remediation for a finding",
)
def upsert_remediation(
    finding_id: str,
    payload: RemediationUpdate,
    session: DbSession,
    context=require("remediation:write"),
) -> RemediationOut:
    """Set the owner, priority, due date, or notes for a finding's remediation.

    Creating and updating are the same call because a caller almost always wants
    "make it look like this", not "create exactly once".
    """
    finding = session.get(Finding, finding_id)
    if finding is None or finding.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    record = finding.remediation
    created = record is None
    if record is None:
        record = Remediation(
            organization_id=context.organization.id,
            finding_id=finding.id,
            priority=_default_priority(finding.severity),
        )
        session.add(record)

    changes: list[str] = []
    if payload.owner is not None and payload.owner != record.owner:
        changes.append(f"owner {record.owner.value} -> {payload.owner.value}")
        record.owner = payload.owner
    if payload.assignee_user_id is not None and payload.assignee_user_id != record.assignee_user_id:
        if payload.assignee_user_id:
            from veyl_api.models import OrganizationMember

            member = session.get(OrganizationMember, payload.assignee_user_id)
            if member is None or member.organization_id != context.organization.id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="assignee is not a member of this organization",
                )
        changes.append(f"assignee -> {payload.assignee_user_id or 'unassigned'}")
        record.assignee_user_id = payload.assignee_user_id or None
    if payload.priority is not None and payload.priority != record.priority:
        changes.append(f"priority {record.priority} -> {payload.priority}")
        record.priority = payload.priority
    if payload.due_date is not None and payload.due_date != record.due_date:
        changes.append(f"due_date -> {payload.due_date.isoformat()}")
        record.due_date = payload.due_date
    if payload.notes is not None and payload.notes != record.notes:
        changes.append("notes updated")
        record.notes = payload.notes

    session.add(
        FindingEvent(
            organization_id=context.organization.id,
            finding_id=finding.id,
            event_type="REMEDIATION_CREATED" if created else "REMEDIATION_UPDATED",
            detail="; ".join(changes) if changes else "no effective change",
            actor_user_id=context.user.id,
            actor_label=context.user.email,
            created_at=utcnow(),
        )
    )
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.REMEDIATION_UPDATED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="finding",
            resource_id=finding.id,
            detail=("created remediation; " if created else "") + ("; ".join(changes) or "no change"),
        ),
    )
    session.commit()
    session.refresh(record)
    return _remediation_out(record)


def _default_priority(severity: Severity) -> str:
    """Derive a starting priority from severity.

    Only a default: the point of the field is that a human can override it,
    because consequence depends on context that severity does not carry.
    """
    return {
        Severity.CRITICAL: "URGENT",
        Severity.HIGH: "HIGH",
        Severity.MEDIUM: "MEDIUM",
        Severity.LOW: "LOW",
        Severity.INFO: "LOW",
    }.get(severity, "MEDIUM")
