"""Scope registry, assets, and scan submission.

The scope registry is the authorization boundary made explicit. Two behaviours
in this module are load-bearing for the product's safety claim:

* **A scope entry can be created, but it cannot authorize itself.** Creating an
  entry defaults to ``PENDING``. Only an explicit status change to ``AUTHORIZED``
  makes it scannable, and that change is audited with who made it.
* **Scan submission re-checks authorization at submit time, not just at
  creation.** An entry that expired, was revoked, or was deactivated between
  creation and submission is refused with the specific reason, and the refusal
  is recorded on the scan.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from veyl_api.api.deps import DbSession, require
from veyl_api.api.schemas import (
    AssetContextOut,
    AssetContextUpdate,
    AssetDetail,
    AssetSummary,
    CertificateOut,
    DashboardSummary,
    FindingSummary,
    Page,
    ScanCreate,
    ScanOut,
    ScopeEntryCreate,
    ScopeEntryOut,
    ScopeEntryUpdate,
    ServiceOut,
)
from veyl_api.audit import AuditRecord, write_audit
from veyl_api.db.base import utcnow
from veyl_api.enums import (
    AssetStatus,
    AuditAction,
    FindingStatus,
    Severity,
    VulnerabilityStatus,
)
from veyl_api.models import (
    Asset,
    AssetContext,
    Certificate,
    Finding,
    Remediation,
    Scan,
    ScopeEntry,
    Service,
)
from veyl_api.safety.scope import ScopeGuard

scope_router = APIRouter()
router = APIRouter()
scans_router = APIRouter()
dashboard_router = APIRouter()

#: Severity ordering for "highest severity on this asset" and for sorting.
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


# =============================================================================
# Scope registry
# =============================================================================


def _scope_out(entry: ScopeEntry) -> ScopeEntryOut:
    return ScopeEntryOut(
        id=entry.id,
        domain=entry.domain,
        cidr=entry.cidr,
        environment=entry.environment,
        asset_owner=entry.asset_owner,
        authorization_status=entry.authorization_status,
        authorized_by=entry.authorized_by,
        authorized_at=entry.authorized_at,
        expires_at=entry.expires_at,
        notes=entry.notes,
        is_active=entry.is_active,
        allow_port_override=entry.allow_port_override,
        is_authorized_now=entry.is_authorized_now,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


@scope_router.get("", response_model=Page, summary="List scope entries")
def list_scope(
    session: DbSession,
    context=require("scope:read"),
    include_inactive: bool = True,
    authorization_status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0),
) -> Page:
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    conditions = [ScopeEntry.organization_id == context.organization.id]
    if not include_inactive:
        conditions.append(ScopeEntry.is_active.is_(True))
    if authorization_status:
        conditions.append(ScopeEntry.authorization_status == authorization_status)

    total = session.execute(
        select(func.count()).select_from(ScopeEntry).where(*conditions)
    ).scalar_one()

    stmt = (
        select(ScopeEntry)
        .where(*conditions)
        .order_by(ScopeEntry.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = list(session.execute(stmt).scalars())
    return Page(total=total, limit=limit, offset=offset, items=[_scope_out(e) for e in rows])


@scope_router.post(
    "",
    response_model=ScopeEntryOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a target to the scope registry",
)
def create_scope_entry(
    payload: ScopeEntryCreate, session: DbSession, context=require("scope:write")
) -> ScopeEntryOut:
    """Register a target.

    The entry is created with whatever authorization status was supplied, but
    defaults to PENDING. Registering a target is not the same as authorizing it,
    and the API keeps those two acts separate.
    """
    domain = payload.domain.strip().lower().rstrip(".")

    if payload.cidr:
        import ipaddress

        try:
            ipaddress.ip_network(payload.cidr, strict=False)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"invalid CIDR {payload.cidr!r}: {exc}",
            ) from exc

    duplicate = session.execute(
        select(ScopeEntry).where(
            ScopeEntry.organization_id == context.organization.id,
            ScopeEntry.domain == domain,
            ScopeEntry.cidr == payload.cidr,
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"scope entry for {domain!r} already exists (id {duplicate.id})",
        )

    authorized = payload.authorization_status.value == "AUTHORIZED"
    entry = ScopeEntry(
        organization_id=context.organization.id,
        domain=domain,
        cidr=payload.cidr,
        environment=payload.environment,
        asset_owner=payload.asset_owner,
        authorization_status=payload.authorization_status,
        authorized_by=payload.authorized_by or context.user.email,
        authorized_at=utcnow() if authorized else None,
        expires_at=payload.expires_at,
        notes=payload.notes,
        is_active=payload.is_active,
        allow_port_override=payload.allow_port_override,
    )
    session.add(entry)
    session.flush()

    write_audit(
        session,
        AuditRecord(
            action=AuditAction.SCOPE_CREATED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="scope_entry",
            resource_id=entry.id,
            detail=(
                f"registered {domain}"
                + (f" ({payload.cidr})" if payload.cidr else "")
                + f" with status {payload.authorization_status.value}"
            ),
        ),
    )
    session.commit()
    session.refresh(entry)
    return _scope_out(entry)


@scope_router.get("/{entry_id}", response_model=ScopeEntryOut, summary="Fetch a scope entry")
def get_scope_entry(
    entry_id: str, session: DbSession, context=require("scope:read")
) -> ScopeEntryOut:
    entry = session.get(ScopeEntry, entry_id)
    if entry is None or entry.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scope entry not found")
    return _scope_out(entry)


@scope_router.patch(
    "/{entry_id}", response_model=ScopeEntryOut, summary="Update a scope entry"
)
def update_scope_entry(
    entry_id: str,
    payload: ScopeEntryUpdate,
    session: DbSession,
    context=require("scope:write"),
) -> ScopeEntryOut:
    """Update a scope entry, including its authorization status.

    Changing the status to AUTHORIZED is the act that makes a target scannable,
    so it is recorded with the previous value and the acting user.
    """
    entry = session.get(ScopeEntry, entry_id)
    if entry is None or entry.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scope entry not found")

    changes: list[str] = []

    if (
        payload.authorization_status is not None
        and payload.authorization_status != entry.authorization_status
    ):
        changes.append(
            f"authorization_status {entry.authorization_status.value} -> "
            f"{payload.authorization_status.value}"
        )
        entry.authorization_status = payload.authorization_status
        if payload.authorization_status.value == "AUTHORIZED":
            entry.authorized_at = utcnow()
            entry.authorized_by = payload.authorized_by or context.user.email
        else:
            # Revoking clears the attestation: a later re-authorization must set
            # it again rather than inherit a stale claim.
            entry.authorized_at = None
    elif payload.authorized_by is not None:
        entry.authorized_by = payload.authorized_by

    if payload.environment is not None and payload.environment != entry.environment:
        changes.append(f"environment {entry.environment.value} -> {payload.environment.value}")
        entry.environment = payload.environment
    if payload.asset_owner is not None and payload.asset_owner != entry.asset_owner:
        changes.append(f"asset_owner {entry.asset_owner.value} -> {payload.asset_owner.value}")
        entry.asset_owner = payload.asset_owner
    if payload.expires_at is not None and payload.expires_at != entry.expires_at:
        changes.append(f"expires_at -> {payload.expires_at.isoformat()}")
        entry.expires_at = payload.expires_at
    if payload.notes is not None and payload.notes != entry.notes:
        changes.append("notes updated")
        entry.notes = payload.notes
    if payload.is_active is not None and payload.is_active != entry.is_active:
        changes.append(f"is_active {entry.is_active} -> {payload.is_active}")
        entry.is_active = payload.is_active
    if (
        payload.allow_port_override is not None
        and payload.allow_port_override != entry.allow_port_override
    ):
        changes.append(f"allow_port_override -> {payload.allow_port_override}")
        entry.allow_port_override = payload.allow_port_override

    action = AuditAction.SCOPE_UPDATED
    if any(c.startswith("authorization_status") for c in changes):
        action = AuditAction.SCOPE_AUTHORIZATION_CHANGED

    if changes:
        write_audit(
            session,
            AuditRecord(
                action=action,
                organization_id=context.organization.id,
                actor_user_id=context.user.id,
                actor_email=context.user.email,
                actor_role=context.role.value,
                resource_type="scope_entry",
                resource_id=entry.id,
                detail=f"{entry.domain}: " + "; ".join(changes),
            ),
        )
    session.commit()
    session.refresh(entry)
    return _scope_out(entry)


@scope_router.delete(
    "/{entry_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scope entry",
)
def delete_scope_entry(
    entry_id: str, session: DbSession, context=require("scope:write")
) -> Response:
    """Remove a target from the registry.

    The entry is deleted rather than archived, and assets discovered under it are
    retained: deleting an authorization should not erase the evidence of what was
    found while it was authorized.
    """
    entry = session.get(ScopeEntry, entry_id)
    if entry is None or entry.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scope entry not found")

    write_audit(
        session,
        AuditRecord(
            action=AuditAction.SCOPE_DELETED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="scope_entry",
            resource_id=entry.id,
            detail=f"removed {entry.domain} from the scope registry",
        ),
    )
    session.delete(entry)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# =============================================================================
# Assets
# =============================================================================


def _service_out(service: Service) -> ServiceOut:
    return ServiceOut(
        id=service.id,
        port=service.port,
        protocol=service.protocol,
        service_name=service.service_name,
        product=service.product,
        version=service.version,
        banner=service.banner,
        fingerprint_source=service.fingerprint_source,
        confidence=service.confidence,
        is_encrypted=service.is_encrypted,
        first_seen=service.first_seen,
        last_seen=service.last_seen,
    )


def _certificate_out(cert: Certificate) -> CertificateOut:
    return CertificateOut(
        id=cert.id,
        subject=cert.subject,
        issuer=cert.issuer,
        serial_number=cert.serial_number,
        not_before=cert.not_before,
        not_after=cert.not_after,
        days_until_expiry=cert.days_until_expiry,
        is_expired=cert.is_expired,
        is_self_signed=cert.is_self_signed,
        signature_algorithm=cert.signature_algorithm,
        key_size=cert.key_size,
        hostnames=list(cert.hostnames or []),
    )


def _asset_finding_stats(session: DbSession, org_id: str, asset_ids: list[str]):
    """Open-finding count and highest severity per asset, in two queries.

    Done as an aggregate rather than per-asset lookups so listing 200 assets
    costs two queries instead of 400.
    """
    if not asset_ids:
        return {}, {}

    rows = session.execute(
        select(Finding.asset_id, Finding.severity, func.count())
        .where(
            Finding.organization_id == org_id,
            Finding.asset_id.in_(asset_ids),
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]),
        )
        .group_by(Finding.asset_id, Finding.severity)
    ).all()

    counts: dict[str, int] = {}
    worst: dict[str, Severity] = {}
    for asset_id, severity, count in rows:
        counts[asset_id] = counts.get(asset_id, 0) + count
        current = worst.get(asset_id)
        if current is None or _SEVERITY_ORDER.index(severity) < _SEVERITY_ORDER.index(current):
            worst[asset_id] = severity
    return counts, worst


def _asset_summary(
    asset: Asset, open_count: int = 0, highest: Severity | None = None
) -> AssetSummary:
    return AssetSummary(
        id=asset.id,
        asset_key=asset.asset_key,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        domain=asset.domain,
        asset_type=asset.asset_type,
        environment=asset.environment,
        status=asset.status,
        reachable=asset.reachable,
        internet_exposed=asset.internet_exposed,
        authorization_status=asset.authorization_status,
        business_criticality=asset.business_criticality,
        data_classification=asset.data_classification,
        business_function=asset.business_function,
        owner=asset.owner,
        first_seen=asset.first_seen,
        last_seen=asset.last_seen,
        open_finding_count=open_count,
        highest_severity=highest,
    )


@router.get("", response_model=Page, summary="List assets")
def list_assets(
    session: DbSession,
    context=require("asset:read"),
    environment: str | None = None,
    asset_type: str | None = None,
    status_filter: str | None = None,
    criticality: str | None = None,
    reachable: bool | None = None,
    internet_exposed: bool | None = None,
    search: str | None = None,
    limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0),
) -> Page:
    """List assets with filters.

    ``reachable`` and ``internet_exposed`` are separate filters on purpose: a
    customer asking "what can we actually reach" and one asking "what faces the
    internet" are asking different questions.
    """
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    conditions = [Asset.organization_id == context.organization.id]
    if environment:
        conditions.append(Asset.environment == environment)
    if asset_type:
        conditions.append(Asset.asset_type == asset_type)
    if status_filter:
        conditions.append(Asset.status == status_filter)
    if criticality:
        conditions.append(Asset.business_criticality == criticality)
    if reachable is not None:
        conditions.append(Asset.reachable.is_(reachable))
    if internet_exposed is not None:
        conditions.append(Asset.internet_exposed.is_(internet_exposed))
    if search:
        pattern = f"%{search.strip().lower()}%"
        conditions.append(
            or_(
                func.lower(Asset.asset_key).like(pattern),
                func.lower(func.coalesce(Asset.hostname, "")).like(pattern),
                func.lower(func.coalesce(Asset.ip_address, "")).like(pattern),
            )
        )

    total = session.execute(
        select(func.count()).select_from(Asset).where(*conditions)
    ).scalar_one()

    stmt = (
        select(Asset)
        .where(*conditions)
        .order_by(Asset.business_criticality.desc(), Asset.asset_key.asc())
        .limit(limit)
        .offset(offset)
    )
    rows = list(session.execute(stmt).scalars())
    counts, worst = _asset_finding_stats(session, context.organization.id, [a.id for a in rows])

    return Page(
        total=total,
        limit=limit,
        offset=offset,
        items=[
            _asset_summary(a, counts.get(a.id, 0), worst.get(a.id)) for a in rows
        ],
    )


@router.get("/{asset_id}", response_model=AssetDetail, summary="Fetch an asset in full")
def get_asset(asset_id: str, session: DbSession, context=require("asset:read")) -> AssetDetail:
    stmt = (
        select(Asset)
        .where(Asset.id == asset_id, Asset.organization_id == context.organization.id)
        .options(selectinload(Asset.services), selectinload(Asset.certificates))
    )
    asset = session.execute(stmt).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")

    counts, worst = _asset_finding_stats(session, context.organization.id, [asset.id])
    base = _asset_summary(asset, counts.get(asset.id, 0), worst.get(asset.id))

    return AssetDetail(
        **base.model_dump(),
        discovery_source=asset.discovery_source,
        source_provenance=asset.source_provenance,
        scope_entry_id=asset.scope_entry_id,
        context_source=asset.context_source,
        services=[_service_out(s) for s in sorted(asset.services, key=lambda s: s.port)],
        certificates=[_certificate_out(c) for c in asset.certificates],
    )


@router.get(
    "/{asset_id}/context",
    response_model=AssetContextOut,
    summary="Fetch an asset's business context",
)
def get_asset_context(
    asset_id: str, session: DbSession, context=require("asset:read")
) -> AssetContextOut:
    asset = session.get(Asset, asset_id)
    if asset is None or asset.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")

    record = asset.context
    if record is None:
        # Report the asset's denormalised defaults rather than 404: the asset
        # exists and does have a context, it simply has never been enriched.
        # Confidence is LOW because nothing here came from a person.
        return AssetContextOut(
            business_criticality=asset.business_criticality,
            data_classification=asset.data_classification,
            business_function=asset.business_function,
            owner=asset.owner,
            owner_name=None,
            business_description=None,
            context_source=asset.context_source,
            context_confidence="LOW",
            updated_at=asset.updated_at,
        )

    return AssetContextOut(
        business_criticality=record.business_criticality,
        data_classification=record.data_classification,
        business_function=record.business_function,
        owner=record.owner,
        owner_name=record.owner_name,
        business_description=record.business_description,
        context_source=record.context_source,
        context_confidence=record.context_confidence,
        updated_at=record.updated_at,
    )


@router.put(
    "/{asset_id}/context",
    response_model=AssetContextOut,
    summary="Set an asset's business context",
)
def update_asset_context(
    asset_id: str,
    payload: AssetContextUpdate,
    session: DbSession,
    context=require("asset:write"),
) -> AssetContextOut:
    """Record business context supplied by a human.

    This is the one place ``internet_exposed`` can be set, because it is a claim
    about the asset's network position that only the organization can make.
    Setting it rescoring happens on the next scan or on demand; this endpoint
    records the fact, and points callers at the rescore endpoint for the effect.

    Context written here is marked ``USER_PROVIDED`` with the supplying user
    recorded, so a report can always distinguish it from what Veyl measured.
    """
    asset = session.get(Asset, asset_id)
    if asset is None or asset.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")

    record = asset.context
    if record is None:
        record = AssetContext(
            organization_id=context.organization.id,
            asset_id=asset.id,
            business_criticality=asset.business_criticality,
            data_classification=asset.data_classification,
            business_function=asset.business_function,
            owner=asset.owner,
            context_source="USER_PROVIDED",
            context_confidence="HIGH",
        )
        session.add(record)

    changes: list[str] = []
    field_map = (
        ("business_criticality", "business_criticality"),
        ("data_classification", "data_classification"),
        ("business_function", "business_function"),
        ("owner", "owner"),
        ("owner_name", "owner_name"),
        ("business_description", "business_description"),
        ("context_confidence", "context_confidence"),
    )
    for attr, _ in field_map:
        value = getattr(payload, attr, None)
        if value is None:
            continue
        current = getattr(record, attr, None)
        if value != current:
            changes.append(f"{attr} {current!r} -> {value!r}")
            setattr(record, attr, value)
            # Mirror onto the asset so list views stay consistent.
            if hasattr(asset, attr):
                setattr(asset, attr, value)

    exposure_changed = False
    if payload.internet_exposed is not None and payload.internet_exposed != asset.internet_exposed:
        changes.append(f"internet_exposed {asset.internet_exposed} -> {payload.internet_exposed}")
        asset.internet_exposed = payload.internet_exposed
        exposure_changed = True

    if payload.owner_name is not None:
        record.owner_name = payload.owner_name
    if payload.business_description is not None:
        record.business_description = payload.business_description

    # Any human edit makes the context user-provided; a value asserted by a
    # person must never keep the INFERRED label it may have had.
    record.context_source = "USER_PROVIDED"
    record.updated_by_user_id = context.user.id
    asset.context_source = "USER_PROVIDED"

    write_audit(
        session,
        AuditRecord(
            action=AuditAction.ASSET_CONTEXT_UPDATED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="asset",
            resource_id=asset.id,
            detail="; ".join(changes) if changes else "no effective change",
            metadata={"internet_exposed_changed": exposure_changed},
        ),
    )
    session.commit()
    session.refresh(record)
    return AssetContextOut(
        business_criticality=record.business_criticality,
        data_classification=record.data_classification,
        business_function=record.business_function,
        owner=record.owner,
        owner_name=record.owner_name,
        business_description=record.business_description,
        context_source=record.context_source,
        context_confidence=record.context_confidence,
        updated_at=record.updated_at,
    )


@router.post(
    "/{asset_id}/rescore",
    response_model=dict,
    summary="Recompute finding risk scores against current context",
)
def rescore_asset(
    asset_id: str, session: DbSession, context=require("finding:write")
) -> dict:
    """Re-run the risk model for this asset's findings.

    Needed because findings are scored when a scan runs, and business context is
    usually supplied afterwards. Without this, a finding keeps the score it got
    when the asset was unclassified — which is precisely the wrong priority.
    """
    asset = session.get(Asset, asset_id)
    if asset is None or asset.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")

    from veyl_analyzer import rescore_findings

    updated = rescore_findings(
        session,
        organization_id=context.organization.id,
        asset_ids=[asset.id],
    )
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.FINDING_RESCORED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="asset",
            resource_id=asset.id,
            detail=f"rescored {updated} finding(s)",
        ),
    )
    session.commit()
    return {"asset_id": asset.id, "findings_rescored": updated}


# =============================================================================
# Scans
# =============================================================================


def _scan_out(scan: Scan) -> ScanOut:
    return ScanOut(
        id=scan.id,
        status=scan.status,
        trigger=scan.trigger,
        label=scan.label,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        ports_scanned=scan.ports_scanned,
        scanner_backend=scan.scanner_backend,
        targets_requested=scan.targets_requested,
        targets_scanned=scan.targets_scanned,
        targets_blocked=scan.targets_blocked,
        assets_found=scan.assets_found,
        services_found=scan.services_found,
        findings_created=scan.findings_created,
        changes_detected=scan.changes_detected,
        error_message=scan.error_message,
        blocked_targets=list(scan.blocked_targets or []),
        created_at=scan.created_at,
    )


@scans_router.get("", response_model=Page, summary="List scans")
def list_scans(
    session: DbSession,
    context=require("scan:read"),
    status_filter: str | None = None,
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
) -> Page:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    conditions = [Scan.organization_id == context.organization.id]
    if status_filter:
        conditions.append(Scan.status == status_filter)

    total = session.execute(
        select(func.count()).select_from(Scan).where(*conditions)
    ).scalar_one()

    stmt = (
        select(Scan)
        .where(*conditions)
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = list(session.execute(stmt).scalars())
    return Page(total=total, limit=limit, offset=offset, items=[_scan_out(s) for s in rows])


@scans_router.post(
    "",
    response_model=ScanOut,
    status_code=status.HTTP_201_CREATED,
    summary="Run an authorized scan",
)
def create_scan(
    payload: ScanCreate, session: DbSession, context=require("scan:create")
) -> ScanOut:
    """Assess every currently authorized target, or the named subset.

    Authorization is resolved here, freshly, so a target whose attestation lapsed
    cannot be scanned by submitting a scan request. Refused targets are recorded
    on the scan with their reason rather than silently dropped.
    """
    guard = ScopeGuard(session, context.organization.id)

    if payload.scope_entry_ids:
        requested: list[ScopeEntry] = []
        for entry_id in payload.scope_entry_ids:
            entry = session.get(ScopeEntry, entry_id)
            if entry is None or entry.organization_id != context.organization.id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"scope entry {entry_id} not found",
                )
            requested.append(entry)
        usable = [
            e for e in requested if e.is_authorized_now and e.authorization_status.value == "AUTHORIZED"
        ]
        refused = [e for e in requested if e not in usable]
    else:
        usable = guard.authorized_targets()
        refused = [
            e
            for e in guard.all_entries()
            if e not in usable
        ]

    if payload.port_override:
        # A port override is only honored for entries that explicitly opted in.
        # Silently ignoring it would produce a scan that does not match what was
        # asked for; silently honoring it would scan ports nobody authorized.
        not_opted_in = [e for e in usable if not e.allow_port_override]
        if not_opted_in:
            names = ", ".join(e.domain for e in not_opted_in[:5])
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "port_override was supplied but these scope entries do not permit it: "
                    f"{names}. Set allow_port_override on the scope entry, or scan the "
                    "default port set."
                ),
            )

    if not usable:
        reasons = [
            {
                "domain": e.domain,
                "reason": (
                    "inactive"
                    if not e.is_active
                    else "not authorized"
                    if e.authorization_status.value != "AUTHORIZED"
                    else "expired"
                ),
            }
            for e in refused[:20]
        ]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": (
                    "no authorized, unexpired, active scope entries are available to scan; "
                    "add a target to the scope registry and mark it AUTHORIZED"
                ),
                "refused": reasons,
            },
        )

    scan = Scan(
        organization_id=context.organization.id,
        status="RUNNING",
        trigger=payload.trigger,
        label=payload.label,
        started_at=utcnow(),
        created_by_user_id=context.user.id,
        scope_entry_ids=[e.id for e in usable],
        targets_requested=len(usable),
        scanner_backend="tcp_connect",
    )
    session.add(scan)
    session.flush()

    write_audit(
        session,
        AuditRecord(
            action=AuditAction.SCAN_STARTED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="scan",
            resource_id=scan.id,
            detail=(
                f"scan of {len(usable)} authorized target(s); "
                f"port_override={payload.port_override or 'default'}"
            ),
        ),
    )
    session.commit()

    # The scan itself runs synchronously here. A production deployment would
    # enqueue it; doing so without a worker running would look like a working
    # feature and behave like a hang, so the API runs it inline and returns the
    # finished scan.
    from veyl_scanner import ScanRunner

    runner = ScanRunner(
        session,
        organization_id=context.organization.id,
        created_by_user_id=context.user.id,
        trigger=payload.trigger,
        label=payload.label,
        port_override=payload.port_override,
    )
    try:
        outcome = runner.run(scan, scope_entry_ids=[e.id for e in usable])
    except Exception as exc:  # noqa: BLE001 - recorded on the scan, not swallowed
        scan.status = "FAILED"
        scan.finished_at = utcnow()
        scan.error_message = f"{type(exc).__name__}: {exc}"
        write_audit(
            session,
            AuditRecord(
                action=AuditAction.SCAN_FAILED,
                organization_id=context.organization.id,
                actor_user_id=context.user.id,
                actor_email=context.user.email,
                actor_role=context.role.value,
                resource_type="scan",
                resource_id=scan.id,
                result="FAILURE",
                detail=scan.error_message,
            ),
        )
        session.commit()
        session.refresh(scan)
        return _scan_out(scan)

    session.refresh(scan)
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.SCAN_COMPLETED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="scan",
            resource_id=scan.id,
            result="SUCCESS" if scan.status == "COMPLETED" else "FAILURE",
            detail=(
                f"scanned {scan.targets_scanned}/{scan.targets_requested} target(s); "
                f"{scan.findings_created} finding(s); {scan.changes_detected} change(s); "
                f"{len(outcome.blocked)} target(s) refused"
            ),
        ),
    )
    session.commit()
    session.refresh(scan)
    return _scan_out(scan)


@scans_router.get("/{scan_id}", response_model=ScanOut, summary="Fetch a scan")
def get_scan(scan_id: str, session: DbSession, context=require("scan:read")) -> ScanOut:
    scan = session.get(Scan, scan_id)
    if scan is None or scan.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return _scan_out(scan)


# =============================================================================
# Dashboard
# =============================================================================


@dashboard_router.get("", response_model=DashboardSummary, summary="Dashboard summary")
def dashboard(
    session: DbSession, context=require("org:read"), top: int = 5
) -> DashboardSummary:
    """One call for the numbers a landing page needs.

    Aggregated server-side so the UI does not have to fetch every finding to
    count them.
    """
    org_id = context.organization.id
    top = max(0, min(top, 20))

    asset_count = session.execute(
        select(func.count()).select_from(Asset).where(Asset.organization_id == org_id)
    ).scalar_one()
    reachable_count = session.execute(
        select(func.count())
        .select_from(Asset)
        .where(Asset.organization_id == org_id, Asset.reachable.is_(True))
    ).scalar_one()
    exposed_count = session.execute(
        select(func.count())
        .select_from(Asset)
        .where(Asset.organization_id == org_id, Asset.internet_exposed.is_(True))
    ).scalar_one()

    scope_rows = list(
        session.execute(
            select(ScopeEntry).where(ScopeEntry.organization_id == org_id)
        ).scalars()
    )
    authorized_scope = sum(1 for e in scope_rows if e.is_authorized_now)

    severity_rows = session.execute(
        select(Finding.severity, func.count())
        .where(
            Finding.organization_id == org_id,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]),
        )
        .group_by(Finding.severity)
    ).all()
    by_severity = {severity.value: count for severity, count in severity_rows}
    open_total = sum(by_severity.values())

    from datetime import timedelta

    from veyl_api.models import ExposureChange

    since = utcnow() - timedelta(days=30)
    risk_changes = session.execute(
        select(func.count())
        .select_from(ExposureChange)
        .where(
            ExposureChange.organization_id == org_id,
            ExposureChange.detected_at >= since,
            ExposureChange.is_risk_increasing.is_(True),
        )
    ).scalar_one()

    from veyl_api.models import AttackPath

    active_paths = session.execute(
        select(func.count())
        .select_from(AttackPath)
        .where(AttackPath.organization_id == org_id, AttackPath.is_active.is_(True))
    ).scalar_one()

    last_scan = session.execute(
        select(Scan)
        .where(Scan.organization_id == org_id)
        .order_by(Scan.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    top_findings: list[FindingSummary] = []
    if top:
        rows = list(
            session.execute(
                select(Finding, Asset)
                .join(Asset, Asset.id == Finding.asset_id)
                .where(
                    Finding.organization_id == org_id,
                    Finding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]),
                )
                .order_by(Finding.risk_score.desc())
                .limit(top)
            ).all()
        )
        remediation_ids = set(
            session.execute(
                select(Remediation.finding_id).where(
                    Remediation.finding_id.in_([f.id for f, _ in rows])
                )
            ).scalars()
        )
        for finding, asset in rows:
            top_findings.append(
                FindingSummary(
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
                    asset_id=asset.id,
                    asset_key=asset.asset_key,
                    asset_hostname=asset.hostname,
                    first_seen_at=finding.first_seen_at,
                    last_seen_at=finding.last_seen_at,
                    resolved_at=finding.resolved_at,
                    reopen_count=finding.reopen_count,
                    has_remediation=finding.id in remediation_ids,
                    evidence_count=len(finding.evidence),
                )
            )

    return DashboardSummary(
        asset_count=asset_count,
        reachable_asset_count=reachable_count,
        internet_exposed_asset_count=exposed_count,
        scope_entry_count=len(scope_rows),
        authorized_scope_entry_count=authorized_scope,
        open_finding_count=open_total,
        findings_by_severity=by_severity,
        risk_increasing_changes_30d=risk_changes,
        active_attack_path_count=active_paths,
        last_scan=_scan_out(last_scan) if last_scan else None,
        top_findings=top_findings,
    )
