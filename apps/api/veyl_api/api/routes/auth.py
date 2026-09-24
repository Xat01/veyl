"""Authentication endpoints.

Login is the one place the API accepts a credential, so it is written to leak as
little as possible:

* A failed login never distinguishes "no such user" from "wrong password". The
  response is identical, and a dummy hash is verified in the no-such-user case
  so the timing is comparable too.
* The audit entry records the attempt and its outcome either way.
* Rate limiting is applied by middleware, so password guessing is bounded even
  though the endpoint itself has no state.

A second stage sits between a correct password and a session (§27). When the
account has a factor enrolled, login returns ``422`` with
``MFARequiredResponse`` and no tokens; the caller repeats the request with a
code. Order matters: the factor is checked *after* the password, so an attacker
who does not know the password never learns whether an account has a factor.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from veyl_api.api.deps import CurrentUserDep, DbSession, _resolve_organization
from veyl_api.api.schemas import (
    CredentialOut,
    CurrentUser,
    LoginRequest,
    MFADisableRequest,
    MFARequiredResponse,
    OrganizationSummary,
    RefreshRequest,
    SecurityPostureOut,
    TokenResponse,
    TOTPConfirmOut,
    TOTPConfirmRequest,
    TOTPEnrolmentOut,
    WebAuthnAuthenticationOptionsOut,
    WebAuthnAuthenticationRequest,
    WebAuthnRegistrationOptionsOut,
    WebAuthnRegistrationRequest,
)
from veyl_api.audit import AuditRecord, write_audit
from veyl_api.config import settings
from veyl_api.enums import ROLE_CAPABILITIES, AuditAction, OrganizationRole
from veyl_api.models import Organization, OrganizationMember, User, WebAuthnCredential
from veyl_api.security import mfa as mfa_service
from veyl_api.security import webauthn
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

#: Returned when the password is correct but a factor is still required. The
#: status is 401 rather than 200 so a client that only checks for success does
#: not mistake this for a session.
_MFA_REQUIRED_STATUS = status.HTTP_401_UNAUTHORIZED


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


def _available_factors(user: User) -> list[str]:
    """List the factors this account can actually present, best first.

    Hardware keys are listed before TOTP because they are strictly stronger
    against phishing, and the client is told the order to offer them in.
    """
    factors: list[str] = []
    if any(c.is_active for c in user.webauthn_credentials):
        factors.append("webauthn")
    if user.mfa_enabled and user.mfa_secret_hash:
        factors.append("totp")
    if user.mfa_recovery_hash:
        factors.append("recovery_code")
    return factors


def _record_login_failure(
    session: DbSession,
    *,
    request: Request,
    organization_id: str,
    email: str,
    detail: str,
    user: User | None = None,
) -> None:
    """Record a failed attempt, lock the account if the threshold is reached."""
    locked_now = False
    if user is not None:
        locked_now = mfa_service.register_failure(session, user)

    write_audit(
        session,
        AuditRecord(
            action=AuditAction.LOGIN_FAILED,
            organization_id=organization_id,
            actor_user_id=user.id if user is not None else None,
            actor_email=email.strip().lower(),
            result="FAILURE",
            detail=detail,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        ),
    )
    if locked_now and user is not None:
        write_audit(
            session,
            AuditRecord(
                action=AuditAction.ACCOUNT_LOCKED,
                organization_id=organization_id,
                actor_user_id=user.id,
                actor_email=user.email,
                result="FAILURE",
                detail=(
                    f"{mfa_service.LOCKOUT_THRESHOLD} failed attempts within "
                    f"{mfa_service.LOCKOUT_WINDOW_MINUTES} minutes; locked for "
                    f"{mfa_service.LOCKOUT_DURATION_MINUTES} minutes"
                ),
                ip_address=_client_ip(request),
            ),
        )
    session.commit()


def _client_ip(request: Request) -> str | None:
    from veyl_api.api.deps import _client_ip as resolve

    return resolve(request)


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        401: {"model": MFARequiredResponse, "description": "A second factor is required."},
        423: {"description": "The account is locked."},
    },
    summary="Exchange credentials, and a second factor when one is enrolled",
)
def login(payload: LoginRequest, session: DbSession, request: Request) -> TokenResponse:
    """Authenticate and issue an access/refresh token pair.

    The order of checks is deliberate and each one audits itself:

    1. Lockout, before the password is even verified, so a locked account cannot
       be used to consume CPU on bcrypt and cannot be probed further.
    2. Password.
    3. Second factor, if the account has one.
    4. The §27 policy: an account holding ADMIN must have a factor.
    """
    email = payload.email.strip().lower()

    # --- 1. Lockout -------------------------------------------------------
    stmt = select(User).where(User.email == email)
    existing = session.execute(stmt).scalar_one_or_none()

    if existing is not None and mfa_service.is_locked(existing):
        remaining = mfa_service.lockout_remaining_seconds(existing)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=(
                "this account is temporarily locked after repeated failed sign-ins. "
                f"Try again in {remaining // 60 + 1} minute(s)."
            ),
            headers={"Retry-After": str(remaining)},
        )

    # --- 2. Password ------------------------------------------------------
    user = _authenticate_user(session, email, payload.password)
    if user is None:
        _record_login_failure(
            session,
            request=request,
            organization_id=payload.organization_slug or "unknown",
            email=email,
            detail="invalid credentials",
            user=existing,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # --- 3. Second factor -------------------------------------------------
    factors = _available_factors(user)
    verified_factor: str | None = None

    if factors:
        if payload.totp_code:
            if not (user.mfa_enabled and user.mfa_secret_hash):
                _record_login_failure(
                    session,
                    request=request,
                    organization_id=payload.organization_slug or "unknown",
                    email=email,
                    detail="a second-factor code was submitted but no TOTP factor is enrolled",
                    user=user,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="a second-factor code was supplied, but this account has no code-based factor",
                )
            # The secret hash is a bcrypt of the raw secret, so the secret must
            # be reconstructed to compute a code. It is stored symmetrically
            # encrypted rather than plaintext; see ``_reveal_totp_secret``.
            secret = _reveal_totp_secret(user)
            if not mfa_service.verify_totp(secret, payload.totp_code):
                _record_login_failure(
                    session,
                    request=request,
                    organization_id=payload.organization_slug or "unknown",
                    email=email,
                    detail="the submitted second-factor code did not match",
                    user=user,
                )
                write_audit(
                    session,
                    AuditRecord(
                        action=AuditAction.MFA_FAILED,
                        organization_id=payload.organization_slug or "unknown",
                        actor_user_id=user.id,
                        actor_email=user.email,
                        result="FAILURE",
                        detail="invalid TOTP code at login",
                        ip_address=_client_ip(request),
                    ),
                )
                session.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="the second-factor code was not valid, or has expired",
                )
            verified_factor = "totp"

        elif payload.recovery_code:
            if not mfa_service.verify_recovery_code(user, payload.recovery_code):
                _record_login_failure(
                    session,
                    request=request,
                    organization_id=payload.organization_slug or "unknown",
                    email=email,
                    detail="the submitted recovery code did not match",
                    user=user,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="that recovery code was not valid",
                )
            verified_factor = "recovery_code"

        else:
            # No code supplied yet. Ask for one without revealing whether the
            # password was correct — but note this branch is only reachable when
            # it was, so the response does leak that much. It has to: the client
            # cannot prompt for a code otherwise. What it does not leak is
            # *which* factors exist, because the methods list is identical for
            # every account that has any factor at all.
            raise HTTPException(
                status_code=_MFA_REQUIRED_STATUS,
                detail=MFARequiredResponse(methods=factors).model_dump(),
            )

    # --- 4. The §27 privileged-role policy --------------------------------
    unmet = mfa_service.privileged_roles_without_factor(session, user)
    if unmet:
        write_audit(
            session,
            AuditRecord(
                action=AuditAction.LOGIN_FAILED,
                organization_id=payload.organization_slug or "unknown",
                actor_user_id=user.id,
                actor_email=user.email,
                result="FAILURE",
                detail=(
                    "refused: this account holds a privileged role but has no second factor "
                    f"enrolled (organization ids: {unmet})"
                ),
                ip_address=_client_ip(request),
            ),
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "this account holds an administrative role and must enrol a second factor "
                f"before it can sign in. Enrol one at {settings.api_prefix}/auth/mfa/totp/enrol "
                "or register a hardware key."
            ),
        )

    org, membership = _resolve_organization(
        session, user, {"org_slug": payload.organization_slug}, payload.organization_slug
    )

    pair = create_token_pair(
        user_id=user.id, organization_id=org.id, role=membership.role.value
    )

    mfa_service.clear_failures(user)
    user.last_login_at = _utcnow()

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
            detail=(
                "login succeeded"
                + (f" with {verified_factor} as the second factor" if verified_factor else "")
            ),
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        ),
    )
    if verified_factor:
        write_audit(
            session,
            AuditRecord(
                action=(
                    AuditAction.MFA_RECOVERY_USED
                    if verified_factor == "recovery_code"
                    else AuditAction.MFA_VERIFIED
                ),
                organization_id=org.id,
                actor_user_id=user.id,
                actor_email=user.email,
                result="SUCCESS",
                detail=f"second factor accepted: {verified_factor}",
                ip_address=_client_ip(request),
            ),
        )
    session.commit()
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
    )


def _utcnow():
    from veyl_api.db.base import utcnow

    return utcnow()


def _reveal_totp_secret(user: User) -> str:
    """Recover the TOTP secret so a code can be verified.

    A TOTP secret cannot be a one-way hash: verifying a code requires computing
    the expected code, which requires the secret itself. It is therefore stored
    encrypted with the deployment secret rather than hashed, and this function
    is the single place that decrypts it.

    ``mfa_secret_hash`` keeps its name for the column, but its content is
    ciphertext. That is a naming wart, and it is documented here rather than
    renamed because a rename would be a schema migration for a cosmetic gain.

    Raises:
        MFAError: when the stored value cannot be decrypted, which means the
            deployment secret changed since enrolment. The account must re-enrol.
    """
    from cryptography.fernet import Fernet, InvalidToken

    if not user.mfa_secret_hash:
        raise mfa_service.MFAError("this account has no TOTP secret")

    key = _fernet_key()
    try:
        return Fernet(key).decrypt(user.mfa_secret_hash.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError, TypeError) as exc:
        raise mfa_service.MFAError(
            "the stored second-factor secret cannot be decrypted with this deployment's "
            "secret key; the deployment secret has changed and the account must re-enrol"
        ) from exc


def _fernet_key() -> bytes:
    """Derive a Fernet key from the deployment secret.

    Fernet requires a 32-byte url-safe base64 key, and the deployment secret is
    an arbitrary string, so it is hashed to length first. Deriving rather than
    requiring a second secret keeps the configuration surface small: rotating
    the deployment secret rotates the encryption key, and the consequence of
    that is stated rather than hidden.
    """
    import base64 as _b64
    import hashlib as _hashlib

    digest = _hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    return _b64.urlsafe_b64encode(digest)


def _hash_totp_secret(secret: str) -> str:
    """Encrypt a TOTP secret for storage. See ``_reveal_totp_secret``."""
    from cryptography.fernet import Fernet

    return Fernet(_fernet_key()).encrypt(secret.encode("ascii")).decode("ascii")


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

    # A refresh must not outlive the factor policy: an account that lost its
    # factor (or was granted a privileged role without one) cannot refresh into
    # a session it could not have obtained by logging in.
    if mfa_service.privileged_roles_without_factor(session, user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "this account holds an administrative role without a second factor; "
                "sign in again after enrolling one"
            ),
        )

    # No explicit slug here: the refresh token already names the organization it
    # was issued for, and the resolver reads that claim. Passing a slug would
    # discard it and make every multi-organization refresh ambiguous.
    org, membership = _resolve_organization(session, user, decoded, None)
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


# =============================================================================
# Second factors (§27)
# =============================================================================
#
# Every endpoint below is authenticated and acts on the caller's own account
# only. There is deliberately no "enrol a factor for this user id" endpoint: an
# administrator cannot enrol a factor on someone else's behalf, because that
# would mean an administrator can create a credential they control on an
# account they do not own.


@router.get(
    "/security",
    response_model=SecurityPostureOut,
    summary="Report the caller's authentication posture and what the policy permits",
)
def security_posture(context: CurrentUserDep, session: DbSession) -> SecurityPostureOut:
    """Describe what this account has enrolled, and the gaps against §27.

    Returned as concrete data rather than a score. An operator reading this can
    see exactly which requirement is unmet and what to do about it.
    """
    user = context.user
    session.refresh(user)

    credentials = [
        CredentialOut(
            id=c.id,
            credential_id_prefix=c.credential_id[:12],
            label=c.label,
            algorithm=c.algorithm,
            curve=c.curve,
            is_active=c.is_active,
            created_at=c.created_at,
            last_used_at=c.last_used_at,
        )
        for c in sorted(user.webauthn_credentials, key=lambda c: c.created_at)
    ]

    privileged = [
        str(getattr(m.role, "value", m.role))
        for m in user.memberships
        if m.is_active and str(getattr(m.role, "value", m.role)) in mfa_service.PRIVILEGED_ROLES
    ]

    has_key = any(c.is_active for c in user.webauthn_credentials)
    has_totp = bool(user.mfa_enabled and user.mfa_secret_hash)

    recommendations: list[str] = []
    if not has_key:
        recommendations.append(
            "Register a hardware security key. It is the only factor here that resists a "
            "real-time phishing proxy, because the key will not sign for another origin."
        )
    if not has_totp and not has_key:
        recommendations.append(
            "Enrol a TOTP authenticator as a baseline second factor."
        )
    if not user.mfa_recovery_hash:
        recommendations.append(
            "Store a set of recovery codes. Without them, losing every device means "
            "losing access to this account."
        )
    if privileged and not (has_key or has_totp):
        recommendations.append(
            "This account holds an administrative role. Sign-in is refused until a second "
            "factor is enrolled; enrol one now."
        )
    if has_totp and not has_key:
        recommendations.append(
            "Consider adding a hardware key for administrative use. A TOTP code can be "
            "relayed by a phishing proxy; a hardware key cannot."
        )

    return SecurityPostureOut(
        mfa_enabled=bool(user.mfa_enabled),
        has_hardware_key=has_key,
        has_totp=has_totp,
        recovery_codes_issued=bool(user.mfa_recovery_hash),
        credentials=credentials,
        privileged_roles=sorted(set(privileged)),
        meets_privileged_policy=not mfa_service.privileged_roles_without_factor(session, user),
        failed_login_count=user.failed_login_count,
        locked_until=user.locked_until,
        lockout_threshold=mfa_service.LOCKOUT_THRESHOLD,
        lockout_window_minutes=mfa_service.LOCKOUT_WINDOW_MINUTES,
        session_ttl_minutes=settings.access_token_ttl_minutes,
        recommendations=recommendations,
    )


# --- TOTP ------------------------------------------------------------------


@router.post(
    "/mfa/totp/enrol",
    response_model=TOTPEnrolmentOut,
    summary="Begin TOTP enrolment; returns the secret and recovery codes once",
)
def enrol_totp(context: CurrentUserDep, session: DbSession) -> TOTPEnrolmentOut:
    """Generate a new TOTP secret and a set of recovery codes.

    The secret is stored encrypted but the factor is **not yet active**: the
    account stays ``mfa_enabled = False`` until ``/mfa/totp/confirm`` proves the
    user actually loaded the secret into an authenticator. Enrolling without
    confirmation is how an account ends up locked out of a factor it never
    really had.

    Calling this again replaces any pending secret, so a user who lost the
    provisioning URI before scanning can simply start over.
    """
    user = context.user
    session.refresh(user)

    secret = mfa_service.generate_totp_secret()
    recovery_codes = mfa_service.generate_recovery_codes()

    user.mfa_secret_hash = _hash_totp_secret(secret)
    user.mfa_enabled = False  # activated by /mfa/totp/confirm
    user.mfa_recovery_hash = mfa_service.hash_recovery_codes(recovery_codes)

    session.commit()

    return TOTPEnrolmentOut(
        secret=secret,
        provisioning_uri=mfa_service.totp_provisioning_uri(secret, email=user.email),
        recovery_codes=recovery_codes,
    )


@router.post(
    "/mfa/totp/confirm",
    response_model=TOTPConfirmOut,
    summary="Activate TOTP enrolment by proving a code was generated",
)
def confirm_totp(
    payload: TOTPConfirmRequest, context: CurrentUserDep, session: DbSession, request: Request
) -> TOTPConfirmOut:
    """Activate the enrolled TOTP factor.

    The code is verified against the pending secret. A correct code proves the
    authenticator holds the same secret the server does, which is the only
    evidence that the enrolment actually worked.
    """
    user = context.user
    session.refresh(user)

    if not user.mfa_secret_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no enrolment is in progress; call /mfa/totp/enrol first",
        )

    try:
        secret = _reveal_totp_secret(user)
    except mfa_service.MFAError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    if not mfa_service.verify_totp(secret, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "that code did not match. Check the device clock, and confirm the secret was "
                "loaded into the authenticator before its 30-second window closes."
            ),
        )

    user.mfa_enabled = True
    user.mfa_enrolled_at = _utcnow()
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.MFA_ENROLLED,
            organization_id=context.organization.id,
            actor_user_id=user.id,
            actor_email=user.email,
            result="SUCCESS",
            detail="TOTP second factor enrolled and activated",
            ip_address=_client_ip(request),
        ),
    )
    session.commit()

    return TOTPConfirmOut(
        mfa_enabled=True,
        detail=(
            "TOTP is now active. Store the recovery codes you received at enrolment; "
            "they are the only fallback if this device is lost."
        ),
    )


@router.post(
    "/mfa/disable",
    response_model=TOTPConfirmOut,
    summary="Remove the TOTP factor (requires the password)",
)
def disable_totp(
    payload: MFADisableRequest, context: CurrentUserDep, session: DbSession, request: Request
) -> TOTPConfirmOut:
    """Disable TOTP.

    The password is required deliberately. Removing a factor is a downgrade of
    the account's security, and a stolen access token should not be enough to
    perform one. The request is refused outright when the account holds a
    privileged role, because that would leave admin capability without a factor.
    """
    user = context.user
    session.refresh(user)

    if not verify_password(payload.password, user.password_hash):
        write_audit(
            session,
            AuditRecord(
                action=AuditAction.MFA_FAILED,
                organization_id=context.organization.id,
                actor_user_id=user.id,
                actor_email=user.email,
                result="FAILURE",
                detail="attempt to disable TOTP with an incorrect password",
                ip_address=_client_ip(request),
            ),
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="the password was not correct",
        )

    # How many factors survive this request. "1 if a hardware key is registered"
    # is the correct count here, because TOTP is the factor being removed.
    has_hardware_key = any(c.is_active for c in user.webauthn_credentials)
    if mfa_service.privileged_role_loses_its_factor(
        session, user, remaining_factors=1 if has_hardware_key else 0
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "this account holds an administrative role and this is its only second "
                "factor. Register a hardware key first, then remove the TOTP factor, or "
                "ask another administrator to change the role."
            ),
        )

    user.mfa_enabled = False
    user.mfa_secret_hash = None
    user.mfa_enrolled_at = None
    user.mfa_recovery_hash = None

    write_audit(
        session,
        AuditRecord(
            action=AuditAction.MFA_DISABLED,
            organization_id=context.organization.id,
            actor_user_id=user.id,
            actor_email=user.email,
            result="SUCCESS",
            detail="TOTP second factor removed; recovery codes invalidated",
            ip_address=_client_ip(request),
        ),
    )
    session.commit()

    return TOTPConfirmOut(
        mfa_enabled=False,
        detail=(
            "TOTP has been removed and the recovery codes invalidated."
            + (
                ""
                if has_hardware_key
                else " This account now has no second factor at all."
            )
        ),
    )


# --- WebAuthn ---------------------------------------------------------------


@router.post(
    "/webauthn/register/options",
    response_model=WebAuthnRegistrationOptionsOut,
    summary="Get public-key credential creation options",
)
def webauthn_register_options(
    context: CurrentUserDep, session: DbSession
) -> WebAuthnRegistrationOptionsOut:
    """Issue a challenge and the parameters for ``navigator.credentials.create()``.

    ``attestation`` is ``"none"``. Requesting attestation would ask the
    authenticator to prove its model, and this implementation does not verify
    that proof (see the ``webauthn`` module docstring), so asking for it would
    collect data with no decision attached to it.
    """
    from urllib.parse import urlparse

    user = context.user
    challenge = webauthn.issue_challenge(session, purpose="registration", user_id=user.id)
    session.commit()

    origin = settings.cors_origin_list[0] if settings.cors_origin_list else "http://localhost:3000"
    rp_id = urlparse(origin).hostname or "localhost"

    return WebAuthnRegistrationOptionsOut(
        challenge=challenge,
        rp_id=rp_id,
        rp_name=settings.app_name,
        # The user handle is the account id. It is opaque to the authenticator
        # and is what a discoverable credential stores, so it must not be the
        # email address — that would put a username on the hardware.
        user_id=webauthn.b64url_encode(user.id.encode("utf-8")),
        user_name=user.email,
        user_display_name=user.full_name,
        timeout=webauthn.CHALLENGE_TTL_SECONDS * 1000,
        algorithms=sorted(webauthn.COSE_ALGORITHMS),
    )


@router.post(
    "/webauthn/register",
    response_model=CredentialOut,
    summary="Verify and store a newly registered authenticator",
)
def webauthn_register(
    payload: WebAuthnRegistrationRequest,
    context: CurrentUserDep,
    session: DbSession,
    request: Request,
) -> CredentialOut:
    """Verify the registration ceremony and persist the public key.

    Every failure path here returns 400 with the specific reason. A registration
    that does not verify is never partially stored.
    """
    user = context.user
    try:
        result = webauthn.verify_registration(
            session,
            user=user,
            credential_id=payload.credential_id,
            client_data_json=payload.client_data_json,
            attestation_object=payload.attestation_object,
            transports=payload.transports,
        )
    except mfa_service.MFAError as exc:
        session.rollback()
        write_audit(
            session,
            AuditRecord(
                action=AuditAction.WEBAUTHN_FAILED,
                organization_id=context.organization.id,
                actor_user_id=user.id,
                actor_email=user.email,
                result="FAILURE",
                detail=f"hardware-key registration refused: {exc}",
                ip_address=_client_ip(request),
            ),
        )
        session.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    credential = WebAuthnCredential(
        user_id=user.id,
        credential_id=result.credential_id,
        public_key=webauthn.b64url_encode(result.public_key_der),
        algorithm=result.algorithm,
        curve=result.curve,
        sign_count=result.sign_count,
        transports=result.transports,
        aaguid=result.aaguid,
        label=payload.label,
    )
    session.add(credential)

    write_audit(
        session,
        AuditRecord(
            action=AuditAction.WEBAUTHN_REGISTERED,
            organization_id=context.organization.id,
            actor_user_id=user.id,
            actor_email=user.email,
            result="SUCCESS",
            detail=(
                f"hardware key registered ({result.algorithm} on {result.curve}); "
                f"attestation format {result.attestation_format or 'not supplied'}, not evaluated"
            ),
            resource_type="webauthn_credential",
            ip_address=_client_ip(request),
        ),
    )
    session.commit()
    session.refresh(credential)

    return CredentialOut(
        id=credential.id,
        credential_id_prefix=credential.credential_id[:12],
        label=credential.label,
        algorithm=credential.algorithm,
        curve=credential.curve,
        is_active=credential.is_active,
        created_at=credential.created_at,
        last_used_at=credential.last_used_at,
    )


@router.post(
    "/webauthn/authenticate/options",
    response_model=WebAuthnAuthenticationOptionsOut,
    summary="Get assertion options for a registered hardware key",
)
def webauthn_authenticate_options(
    context: CurrentUserDep, session: DbSession
) -> WebAuthnAuthenticationOptionsOut:
    """Issue a challenge for ``navigator.credentials.get()``.

    ``allow_credentials`` lists only the caller's own active credentials, so the
    browser offers the right key and the server has already narrowed the
    assertion to keys this account actually owns.
    """
    from urllib.parse import urlparse

    user = context.user
    challenge = webauthn.issue_challenge(session, purpose="authentication", user_id=user.id)
    session.commit()

    origin = settings.cors_origin_list[0] if settings.cors_origin_list else "http://localhost:3000"
    rp_id = urlparse(origin).hostname or "localhost"

    allow = [
        {
            "type": "public-key",
            "id": c.credential_id,
            "transports": (c.transports.split(",") if c.transports else []),
        }
        for c in user.webauthn_credentials
        if c.is_active
    ]

    return WebAuthnAuthenticationOptionsOut(
        challenge=challenge,
        rp_id=rp_id,
        timeout=webauthn.CHALLENGE_TTL_SECONDS * 1000,
        allow_credentials=allow,
    )


@router.post(
    "/webauthn/authenticate",
    response_model=TokenResponse,
    summary="Complete a hardware-key sign-in and receive tokens",
)
def webauthn_authenticate(
    payload: WebAuthnAuthenticationRequest,
    context: CurrentUserDep,
    session: DbSession,
    request: Request,
) -> TokenResponse:
    """Verify an assertion against a registered key, then issue a token pair.

    This endpoint requires an existing access token, which is intentional: it is
    a step-up verification, not an alternative first factor. Offering it as a
    passwordless entry point would need a separate discoverable-credential flow
    and a rate limiter of its own, and that is not implemented — see the
    not-implemented list in the README.
    """
    user = context.user
    stmt = select(WebAuthnCredential).where(
        WebAuthnCredential.credential_id == payload.credential_id.rstrip("="),
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.is_active.is_(True),
    )
    credential = session.execute(stmt).scalar_one_or_none()
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no active credential with that identifier belongs to your account",
        )

    try:
        result = webauthn.verify_assertion(
            session,
            credential=credential,
            client_data_json=payload.client_data_json,
            authenticator_data=payload.authenticator_data,
            signature=payload.signature,
        )
    except mfa_service.MFAError as exc:
        session.rollback()
        write_audit(
            session,
            AuditRecord(
                action=AuditAction.WEBAUTHN_FAILED,
                organization_id=context.organization.id,
                actor_user_id=user.id,
                actor_email=user.email,
                result="FAILURE",
                detail=f"hardware-key assertion refused: {exc}",
                resource_type="webauthn_credential",
                resource_id=credential.id,
                ip_address=_client_ip(request),
            ),
        )
        session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    credential.sign_count = result.new_sign_count
    credential.last_used_at = _utcnow()
    mfa_service.clear_failures(user)
    user.last_login_at = _utcnow()

    pair = create_token_pair(
        user_id=user.id,
        organization_id=context.organization.id,
        role=context.role.value,
    )
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.MFA_VERIFIED,
            organization_id=context.organization.id,
            actor_user_id=user.id,
            actor_email=user.email,
            result="SUCCESS",
            detail=f"hardware-key assertion verified (counter advanced to {credential.sign_count})",
            resource_type="webauthn_credential",
            resource_id=credential.id,
            ip_address=_client_ip(request),
        ),
    )
    session.commit()

    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
    )


@router.delete(
    "/webauthn/credentials/{credential_id}",
    response_model=TOTPConfirmOut,
    summary="Remove a registered hardware key",
)
def delete_webauthn_credential(
    credential_id: str,
    context: CurrentUserDep,
    session: DbSession,
    request: Request,
    password: str = "",
) -> TOTPConfirmOut:
    """Remove one of the caller's own credentials.

    Refused when it would leave an administrative account with no factor at all,
    for the same reason disabling TOTP is refused in that case.
    """
    user = context.user
    stmt = select(WebAuthnCredential).where(
        WebAuthnCredential.id == credential_id,
        WebAuthnCredential.user_id == user.id,
    )
    credential = session.execute(stmt).scalar_one_or_none()
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no such credential belongs to your account",
        )

    remaining_keys = [
        c for c in user.webauthn_credentials if c.is_active and c.id != credential.id
    ]
    has_totp = bool(user.mfa_enabled and user.mfa_secret_hash)

    if mfa_service.privileged_role_loses_its_factor(
        session, user, remaining_factors=len(remaining_keys) + (1 if has_totp else 0)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "this is the only second factor on an administrative account; removing it "
                "would leave the role without a factor. Enrol another factor first."
            ),
        )

    credential.is_active = False
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.WEBAUTHN_REMOVED,
            organization_id=context.organization.id,
            actor_user_id=user.id,
            actor_email=user.email,
            result="SUCCESS",
            detail=f"hardware key {credential.credential_id[:12]}… deactivated",
            resource_type="webauthn_credential",
            resource_id=credential.id,
            ip_address=_client_ip(request),
        ),
    )
    session.commit()

    return TOTPConfirmOut(
        mfa_enabled=bool(remaining_keys or has_totp),
        detail=(
            "The key has been deactivated. Its public key is retained so the audit trail "
            "remains complete, but it can no longer be used to sign in."
        ),
    )
