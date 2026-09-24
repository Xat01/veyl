"""FastAPI dependencies: authentication, tenant resolution, and authorization.

The authorization model rests on three invariants, each enforced here rather
than trusted to route authors:

1. **A request has an organization, or it is refused.** Every data route depends
   on ``CurrentContext``, which cannot exist without a resolved membership.
2. **Authorization is re-read from the database on every request.** The JWT
   carries an organization id, but the caller's role is looked up fresh, so
   removing someone's membership takes effect on their next request instead of
   when their token expires.
3. **Missing is not the same as forbidden.** A caller asking for a resource that
   belongs to another tenant gets 404, not 403, so the API cannot be used to
   enumerate other tenants' identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from veyl_api.db.session import get_session
from veyl_api.enums import ROLE_CAPABILITIES, OrganizationRole
from veyl_api.models import Organization, OrganizationMember, User
from veyl_api.security.auth import TokenError, decode_token

bearer_scheme = HTTPBearer(auto_error=False)

UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


@dataclass
class CurrentContext:
    """Everything the caller is allowed to do, resolved per request."""

    user: User
    organization: Organization
    membership: OrganizationMember
    role: OrganizationRole
    capabilities: frozenset[str]
    ip_address: str | None = None

    def require(self, capability: str) -> None:
        """Raise 403 unless the caller holds ``capability``.

        Raises:
            HTTPException: 403 when the capability is absent.
        """
        if capability not in self.capabilities:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"role {self.role.value} is not permitted to perform {capability!r} "
                    f"in this organization"
                ),
            )

    def can(self, capability: str) -> bool:
        return capability in self.capabilities


DbSession = Annotated[Session, Depends(get_session)]


def _client_ip(request: Request) -> str | None:
    """Best-effort client address for the audit log.

    ``X-Forwarded-For`` is only consulted when the deployment declares it
    trustworthy; otherwise a caller could write any address they like into the
    audit trail.
    """
    from veyl_api.config import settings

    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _resolve_organization(
    session: Session, user: User, payload: dict, requested_slug: str | None
) -> tuple[Organization, OrganizationMember]:
    """Pick the organization this request acts within, and prove membership.

    Precedence is explicit: an ``X-Organization`` header from the caller, then
    the organization baked into the token, then — only if the user belongs to
    exactly one — that one. Anything ambiguous is refused rather than guessed,
    because silently picking a tenant is how one customer's data ends up in
    another customer's response.

    Raises:
        HTTPException: 403 when the user has no usable membership; 400 when the
            choice is ambiguous.
    """
    stmt = (
        select(OrganizationMember, Organization)
        .join(Organization, Organization.id == OrganizationMember.organization_id)
        .where(
            OrganizationMember.user_id == user.id,
            OrganizationMember.is_active.is_(True),
        )
    )
    pairs = list(session.execute(stmt).all())

    usable = [(m, o) for m, o in pairs if o.is_active]
    if not usable:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="your account is not an active member of any organization",
        )

    # An explicit header always wins, and is matched by slug or by id so a
    # client is not forced to know which form it holds.
    if requested_slug:
        for membership, org in usable:
            if org.slug == requested_slug or org.id == requested_slug:
                return org, membership
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"you are not a member of organization {requested_slug!r}",
        )

    # The token names the organization the caller logged in under. Honouring it
    # is what makes a multi-organization session usable: without it every
    # follow-up request would be ambiguous.
    token_org_id = payload.get("org") or payload.get("org_id")
    if token_org_id:
        for membership, org in usable:
            if org.id == token_org_id:
                return org, membership
        # The token names an organization the caller is no longer in. Refuse
        # rather than fall through to a different tenant.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="the organization in your token is no longer available to you",
        )

    if len(usable) > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "you belong to multiple organizations; specify one with the "
                "X-Organization header or by logging in with organization_slug"
            ),
        )
    membership, org = usable[0]
    return org, membership


def _authenticate(
    request: Request,
    session: Session,
    credentials: HTTPAuthorizationCredentials | None,
) -> CurrentContext:
    if credentials is None or not credentials.credentials:
        raise UNAUTHENTICATED
    try:
        payload = decode_token(credentials.credentials, expected_type="access")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = payload.get("sub")
    if not user_id:
        raise UNAUTHENTICATED
    user = session.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user no longer exists or is deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    org, membership = _resolve_organization(
        session, user, payload, request.headers.get("x-organization")
    )
    role = membership.role
    return CurrentContext(
        user=user,
        organization=org,
        membership=membership,
        role=role,
        capabilities=ROLE_CAPABILITIES.get(role, frozenset()),
        ip_address=_client_ip(request),
    )


def get_current_context(
    request: Request,
    session: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
) -> CurrentContext:
    """Resolve the caller's identity, organization, and capabilities."""
    return _authenticate(request, session, credentials)


CurrentUserDep = Annotated[CurrentContext, Depends(get_current_context)]


def require(capability: str):
    """Dependency factory enforcing a capability.

    Using this instead of checking inside the handler means the permission is
    part of the route declaration, so it is visible in the OpenAPI schema and
    cannot be forgotten in the middle of a long function body.

    Usage::

        def handler(context: CurrentContext = require("asset:read")) -> ...:
            ...

    The returned function carries ``__veyl_capability__`` so the route table can
    be audited: a test walks every route and asserts it declares a capability,
    which is how a new unguarded endpoint gets caught in review.
    """

    def _dependency(context: CurrentUserDep) -> CurrentContext:
        context.require(capability)
        return context

    _dependency.__name__ = f"require_{capability.replace(':', '_')}"
    _dependency.__veyl_capability__ = capability  # type: ignore[attr-defined]
    return Depends(_dependency)  # noqa: B008 - intentional: FastAPI's idiom


def require_any(*capabilities: str):
    """Dependency factory enforcing that the caller holds at least one."""
    label = "+".join(capabilities)

    def _dependency(context: CurrentUserDep) -> CurrentContext:
        if not capabilities:
            return context
        if not any(cap in context.capabilities for cap in capabilities):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"role {context.role.value} is not permitted to perform this action; "
                    f"requires one of {sorted(capabilities)}"
                ),
            )
        return context

    _dependency.__name__ = f"require_any_{label.replace(':', '_').replace('+', '_')}"
    _dependency.__veyl_capability__ = label  # type: ignore[attr-defined]
    return Depends(_dependency)  # noqa: B008 - intentional: FastAPI's idiom
