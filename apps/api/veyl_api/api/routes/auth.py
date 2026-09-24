"""Authentication endpoints.

Login is the one place the API accepts a credential, so it is written to leak as
little as possible:

* A failed login never distinguishes "no such user" from "wrong password". The
  response is identical, and a dummy hash is verified in the no-such-user case
  so the timing is comparable too.
* The audit entry records the attempt and its outcome either way.
* Rate limiting is applied by middleware, so password guessing is bounded even
  though the endpoint itself has no state.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from veyl_api.api.deps import CurrentUserDep, DbSession, _resolve_organization
from veyl_api.api.schemas import (
    CurrentUser,
    LoginRequest,
    OrganizationSummary,
    RefreshRequest,
    TokenResponse,
)
from veyl_api.audit import AuditRecord, write_audit
from veyl_api.enums import ROLE_CAPABILITIES, AuditAction, OrganizationRole
from veyl_api.models import Organization, OrganizationMember, User
from veyl_api.security.auth import (
    TokenError,
    create_token_pair,
    decode_token,
    verify_password,
)

router = APIRouter()

# Verified against when the user does not exist, so the response time does not
# reveal whether an address is registered. The value is a valid bcrypt hash of a
# random string; it can never match a real password.
_DUMMY_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.6uXqvJ1nVfQmYbLxW3pQqZ9rT8sU1aK"


def _authenticate_user(session: DbSession, email: str, password: str) -> User | None:
    """Return the user if the credentials are valid, else None.

    The password is verified even when the user is missing, so both paths cost
    roughly the same.
    """
    stmt = select(User).where(User.email == email.strip().lower())
    user = session.execute(stmt).scalar_one_or_none()
    if user is None or not user.is_active:
        verify_password(password, _DUMMY_HASH)
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


@router.post("/login", response_model=TokenResponse, summary="Exchange credentials for tokens")
def login(payload: LoginRequest, session: DbSession) -> TokenResponse:
    """Authenticate and issue an access/refresh token pair."""
    user = _authenticate_user(session, payload.email, payload.password)
    if user is None:
        # One audit entry per attempt, recorded before raising so a failed
        # attempt is still evidence.
        write_audit(
            session,
            AuditRecord(
                action=AuditAction.LOGIN_FAILED,
                organization_id=payload.organization_slug or "unknown",
                actor_email=payload.email.strip().lower(),
                result="FAILURE",
                detail="invalid credentials",
            ),
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    org, membership = _resolve_organization(
        session, user, {"org_slug": payload.organization_slug}, payload.organization_slug
    )

    pair = create_token_pair(
        user_id=user.id, organization_id=org.id, role=membership.role.value
    )
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.LOGIN,
            organization_id=org.id,
            actor_user_id=user.id,
            actor_email=user.email,
            actor_role=membership.role.value,
            resource_type="organization",
            resource_id=org.id,
            detail="login succeeded",
        ),
    )
    session.commit()
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
    )


@router.post("/refresh", response_model=TokenResponse, summary="Exchange a refresh token")
def refresh(payload: RefreshRequest, session: DbSession) -> TokenResponse:
    """Issue a new token pair from a valid refresh token.

    The caller's current membership is re-read rather than copied from the old
    token, so a role change or removal is picked up at refresh time.
    """
    try:
        decoded = decode_token(payload.refresh_token, expected_type="refresh")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = decoded.get("sub")
    user = session.get(User, user_id) if user_id else None
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user no longer exists or is deactivated",
        )

    org, membership = _resolve_organization(session, user, decoded, decoded.get("org_slug"))
    pair = create_token_pair(
        user_id=user.id, organization_id=org.id, role=membership.role.value
    )
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
    )


@router.get("/me", response_model=CurrentUser, summary="Describe the authenticated caller")
def me(context: CurrentUserDep, session: DbSession) -> CurrentUser:
    """Return the caller, their organizations, and their permissions.

    Capabilities are computed server-side from the same table the API enforces,
    so a client can hide controls without ever being the authority on access.
    """
    stmt = (
        select(OrganizationMember, Organization)
        .join(Organization, Organization.id == OrganizationMember.organization_id)
        .where(
            OrganizationMember.user_id == context.user.id,
            OrganizationMember.is_active.is_(True),
        )
    )
    memberships = list(session.execute(stmt).all())

    organizations = [
        OrganizationSummary(
            id=org.id,
            name=org.name,
            slug=org.slug,
            role=membership.role,
        )
        for membership, org in memberships
        if org.is_active
    ]

    return CurrentUser(
        id=context.user.id,
        email=context.user.email,
        full_name=context.user.full_name,
        organizations=organizations,
        active_organization_id=context.organization.id,
        role=context.role,
        capabilities=sorted(context.capabilities),
        last_login_at=context.user.last_login_at,
    )


@router.get(
    "/capabilities",
    response_model=dict[str, list[str]],
    summary="List the capabilities granted to each role",
)
def capabilities() -> dict[str, list[str]]:
    """Publish the role/capability matrix.

    Useful to a frontend that wants to render permissions, and to an operator
    auditing what each role can do. It describes the policy; it does not grant
    anything.
    """
    return {
        role.value: sorted(caps) for role, caps in ROLE_CAPABILITIES.items()
    } | {"ROLES": [r.value for r in OrganizationRole]}
