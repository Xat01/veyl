"""Organization membership management.

Members are created directly by an administrator rather than through an
invitation flow, because Veyl has no mail transport. A created member receives a
password the administrator sets and must be told out of band. This is a real
limitation, and the API says so instead of pretending an email was sent.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlalchemy import func, select

from veyl_api.api.deps import DbSession, require
from veyl_api.api.schemas import MemberCreate, MemberSummary, MemberUpdate, Page
from veyl_api.audit import AuditRecord, write_audit
from veyl_api.enums import AuditAction, OrganizationRole
from veyl_api.models import OrganizationMember, User
from veyl_api.security import mfa as mfa_service
from veyl_api.security.auth import hash_password

router = APIRouter()

#: Roles that §27 refuses to grant without a second factor on the account.
#: Imported from the security module rather than redefined so there is exactly
#: one list, and adding a role to the policy cannot leave a gap here.
_PRIVILEGED_ROLES = frozenset(
    OrganizationRole(name) for name in mfa_service.PRIVILEGED_ROLES
)


def _summary(session: DbSession, membership: OrganizationMember) -> MemberSummary:
    user = session.get(User, membership.user_id)
    assert user is not None  # FK guarantees this; asserted for type checkers
    return MemberSummary(
        id=membership.id,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=membership.role,
        is_active=membership.is_active,
        created_at=membership.created_at,
    )


@router.get("", response_model=Page, summary="List organization members")
def list_members(
    session: DbSession,
    context=require("member:read"),
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
) -> Page:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    total = session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == context.organization.id)
    ).scalar_one()

    stmt = (
        select(OrganizationMember)
        .where(OrganizationMember.organization_id == context.organization.id)
        .order_by(OrganizationMember.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    rows = list(session.execute(stmt).scalars())
    return Page(
        total=total,
        limit=limit,
        offset=offset,
        items=[_summary(session, m) for m in rows],
    )


@router.post(
    "",
    response_model=MemberSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Add a member to the organization",
)
def create_member(
    payload: MemberCreate, session: DbSession, context=require("member:write")
) -> MemberSummary:
    """Create a user and add them to this organization.

    If the email already exists as a user, that user is added to this
    organization instead of a duplicate account being created.
    """
    email = payload.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="a valid email address is required",
        )

    user = session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    created_user = False
    if user is None:
        user = User(
            email=email,
            full_name=payload.full_name,
            password_hash=hash_password(payload.password),
            is_active=True,
        )
        session.add(user)
        session.flush()
        created_user = True
    elif not user.full_name and payload.full_name:
        # A user created by an earlier flow may predate the name requirement.
        user.full_name = payload.full_name

    # §27: a privileged role may not be granted to an account that has no second
    # factor. Enforced here as well as at login, because enforcement only at
    # login would leave an account holding ADMIN that can never sign in — a trap
    # for the user rather than a control.
    if payload.role in _PRIVILEGED_ROLES and not mfa_service.has_second_factor(user):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"{email} cannot be granted the {payload.role.value} role yet: an "
                "administrative account must have a second factor enrolled first. Ask them "
                "to enrol one at /api/auth/mfa/totp/enrol or to register a hardware key, "
                "then grant the role."
            ),
        )

    existing = session.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == context.organization.id,
            OrganizationMember.user_id == user.id,
        )
    ).scalar_one_or_none()

    if existing is not None:
        if existing.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{email} is already a member of this organization",
            )
        existing.is_active = True
        existing.role = payload.role
        membership = existing
    else:
        membership = OrganizationMember(
            organization_id=context.organization.id,
            user_id=user.id,
            role=payload.role,
            is_active=True,
        )
        session.add(membership)

    session.flush()
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.MEMBER_ADDED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="member",
            resource_id=user.id,
            detail=(
                f"added {email} as {payload.role.value}"
                + (" (new user account)" if created_user else " (existing user account)")
            ),
        ),
    )
    session.commit()
    session.refresh(membership)
    return _summary(session, membership)


@router.patch(
    "/{member_id}", response_model=MemberSummary, summary="Change a member's role or status"
)
def update_member(
    member_id: str,
    payload: MemberUpdate,
    session: DbSession,
    context=require("member:write"),
) -> MemberSummary:
    """Update a membership.

    An administrator cannot demote or deactivate themselves. Without this rule,
    an organization can be left with no administrator and no way to recover
    through the API.
    """
    membership = session.get(OrganizationMember, member_id)
    # 404 rather than 403 for a cross-tenant id: the API must not confirm that
    # an identifier exists in another organization.
    if membership is None or membership.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="member not found")

    is_self = membership.user_id == context.user.id
    if is_self:
        if payload.role is not None and payload.role != membership.role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="you cannot change your own role; ask another administrator",
            )
        if payload.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="you cannot deactivate your own membership",
            )

    # Refuse to remove the last administrator, however it is attempted.
    losing_admin = (
        membership.role == OrganizationRole.ADMIN
        and (payload.role is not None and payload.role != OrganizationRole.ADMIN)
    ) or (membership.role == OrganizationRole.ADMIN and payload.is_active is False)
    if losing_admin:
        admin_count = session.execute(
            select(func.count())
            .select_from(OrganizationMember)
            .where(
                OrganizationMember.organization_id == context.organization.id,
                OrganizationMember.role == OrganizationRole.ADMIN,
                OrganizationMember.is_active.is_(True),
            )
        ).scalar_one()
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "this is the organization's only administrator; promote another "
                    "member first"
                ),
            )

    changes: list[str] = []
    if payload.role is not None and payload.role != membership.role:
        # §27: promoting into a privileged role requires the account to already
        # have a second factor. Granting first and enrolling later would create a
        # window in which admin capability exists with only a password behind it.
        if payload.role in _PRIVILEGED_ROLES:
            target_user = session.get(User, membership.user_id)
            if target_user is None or not mfa_service.has_second_factor(target_user):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"this account cannot be promoted to {payload.role.value} until it "
                        "has a second factor enrolled; ask the member to enrol one first"
                    ),
                )
        changes.append(f"role {membership.role.value} -> {payload.role.value}")
        membership.role = payload.role
    if payload.is_active is not None and payload.is_active != membership.is_active:
        changes.append(f"active {membership.is_active} -> {payload.is_active}")
        membership.is_active = payload.is_active

    if changes:
        write_audit(
            session,
            AuditRecord(
                action=AuditAction.MEMBER_UPDATED,
                organization_id=context.organization.id,
                actor_user_id=context.user.id,
                actor_email=context.user.email,
                actor_role=context.role.value,
                resource_type="member",
                resource_id=membership.user_id,
                detail="; ".join(changes),
            ),
        )
    session.commit()
    session.refresh(membership)
    return _summary(session, membership)


@router.delete(
    "/{member_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a member from the organization",
)
def remove_member(
    member_id: str, session: DbSession, context=require("member:write")
) -> Response:
    """Delete a membership.

    The user account is left intact: they may belong to other organizations, and
    deleting their account to remove them from one tenant would be a surprising
    side effect.
    """
    membership = session.get(OrganizationMember, member_id)
    if membership is None or membership.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="member not found")

    if membership.user_id == context.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="you cannot remove your own membership",
        )
    if membership.role == OrganizationRole.ADMIN:
        admin_count = session.execute(
            select(func.count())
            .select_from(OrganizationMember)
            .where(
                OrganizationMember.organization_id == context.organization.id,
                OrganizationMember.role == OrganizationRole.ADMIN,
                OrganizationMember.is_active.is_(True),
            )
        ).scalar_one()
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cannot remove the organization's only administrator",
            )

    email = session.get(User, membership.user_id)
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.MEMBER_REMOVED,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="member",
            resource_id=membership.user_id,
            detail=f"removed {email.email if email else membership.user_id}",
        ),
    )
    session.delete(membership)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{member_id}", response_model=MemberSummary, summary="Fetch one member")
def get_member(
    member_id: str, session: DbSession, context=require("member:read")
) -> MemberSummary:
    membership = session.get(OrganizationMember, member_id)
    if membership is None or membership.organization_id != context.organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="member not found")
    return _summary(session, membership)


def new_member_id() -> str:
    """Exposed for tests that need a syntactically valid unused id."""
    return str(uuid.uuid4())
