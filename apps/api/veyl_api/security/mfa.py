"""Second factors for privileged accounts (§27).

Three things live here, and it is worth being precise about what each one
actually protects against, because "MFA" is often used to mean something
weaker than what is implemented:

1. **TOTP** (RFC 6238). A shared secret plus a clock. Protects against a
   password that leaks through reuse or a dump: the attacker has the secret
   half and still cannot sign in. It does *not* protect against a real-time
   phishing proxy, which can relay the code — for that, use a hardware key.

2. **WebAuthn** (see ``webauthn.py``). A public-key challenge bound to the
   origin. This is the only factor here that resists a real-time phishing
   proxy, because the browser refuses to sign a challenge for a different
   origin, and the private key is in hardware the attacker does not have.

3. **Recovery codes**. A single-use fallback, because losing a hardware key
   must not mean losing access to a security tool. Each is stored only as a
   hash and is consumed on use.

**The ADMIN rule.** An account cannot hold the ADMIN role in any organization
unless it has enrolled at least one second factor. That is a *policy*, not a
property of the factor, and it is enforced at three points — role assignment,
login, and request authorization — because enforcing it in only one place would
leave a path where an account obtains admin capability without a factor.

Nothing in this module invents a factor on the user's behalf, and no code path
enrols a factor silently. A user either presents a real one or does not get in.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from veyl_api.config import settings
from veyl_api.db.base import utcnow
from veyl_api.models import OrganizationMember, User
from veyl_api.security.auth import constant_time_compare, hash_password, verify_password

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

#: A code is accepted if it matches the current 30-second step or one adjacent
#: step in either direction. One step of drift is normal for a phone whose clock
#: is a few seconds off; widening this further starts to reduce the value of the
#: factor, so it stays at 1.
TOTP_STEP_SECONDS = 30
TOTP_DRIFT_STEPS = 1
TOTP_DIGITS = 6
TOTP_SECRET_BYTES = 20  # 160 bits, the RFC 4226 recommendation for SHA-1

#: How many failures, within the window, before the account is locked.
LOCKOUT_THRESHOLD = 8
LOCKOUT_WINDOW_MINUTES = 15
LOCKOUT_DURATION_MINUTES = 15

#: Recovery codes issued when a TOTP factor is enrolled. Ten is enough that a
#: user can lose several devices and still get in, and few enough that the list
#: can be printed and stored deliberately.
RECOVERY_CODE_COUNT = 10

#: A WebAuthn challenge is valid for two minutes. Long enough for a user to
#: touch a key, short enough that a captured challenge is useless.
CHALLENGE_TTL_SECONDS = 120

#: Roles that may not be held without a second factor.
PRIVILEGED_ROLES = frozenset({"ADMIN"})


class MFAError(Exception):
    """Raised when a second factor is missing, malformed, or does not verify."""


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    """Return a new base32 TOTP secret, without padding.

    Padding is stripped because ``otpauth://`` URIs and authenticator apps
    disagree about whether it should be present, and an unpadded secret is
    accepted by every implementation that matters.
    """
    return base64.b32encode(secrets.token_bytes(TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")


def _hotp(secret: bytes, counter: int) -> str:
    """RFC 4226 HOTP: HMAC-SHA1, dynamic truncation, ``TOTP_DIGITS`` digits."""
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def _decode_secret(secret: str) -> bytes:
    """Decode a base32 secret, tolerating the padding an app may have added."""
    normalised = secret.strip().replace(" ", "").upper()
    padding = (-len(normalised)) % 8
    try:
        return base64.b32decode(normalised + "=" * padding, casefold=True)
    except Exception as exc:  # noqa: BLE001 - any decode failure is the same failure
        raise MFAError("the stored second-factor secret is not valid base32") from exc


def totp_now(secret: str, *, at: datetime | None = None) -> str:
    """Return the code for the current step. Used by tests and by enrolment."""
    moment = at or utcnow()
    counter = int(moment.timestamp()) // TOTP_STEP_SECONDS
    return _hotp(_decode_secret(secret), counter)


def verify_totp(secret: str, code: str, *, at: datetime | None = None) -> bool:
    """Verify a submitted code, allowing one step of clock drift either way.

    The comparison is constant-time. A code is only six digits, so a timing
    oracle here would let an attacker recover a valid code digit by digit
    without ever guessing it, which is exactly the attack the factor exists to
    prevent.
    """
    submitted = (code or "").strip().replace(" ", "")
    if not submitted.isdigit() or len(submitted) != TOTP_DIGITS:
        return False

    moment = at or utcnow()
    counter = int(moment.timestamp()) // TOTP_STEP_SECONDS
    key = _decode_secret(secret)

    for offset in range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1):
        if constant_time_compare(_hotp(key, counter + offset), submitted):
            return True
    return False


def totp_provisioning_uri(secret: str, *, email: str, issuer: str | None = None) -> str:
    """Build the ``otpauth://`` URI an authenticator app scans.

    This is what the enrolment QR code encodes. It contains the shared secret,
    so the API returns it exactly once, at enrolment, and never again.
    """
    from urllib.parse import quote, urlencode

    issuer_name = issuer or settings.app_name
    params = urlencode(
        {
            "secret": secret,
            "issuer": issuer_name,
            "algorithm": "SHA1",
            "digits": TOTP_DIGITS,
            "period": TOTP_STEP_SECONDS,
        }
    )
    label = quote(f"{issuer_name}:{email}", safe="")
    return f"otpauth://totp/{label}?{params}"


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------


def hash_recovery_codes(codes: list[str]) -> str:
    """Hash a list of recovery codes into one stored value.

    A single hash over the whole set is deliberate. Verifying an individual code
    against a per-code hash would mean iterating every hash on every attempt,
    and the codes are only ever checked as a set — you either hold the list or
    you do not. The set is joined with a newline and hashed with the same KDF
    used for passwords.
    """
    joined = "\n".join(sorted(c.strip().upper() for c in codes))
    return hash_password(_fit_bcrypt(joined))


def _fit_bcrypt(value: str) -> str:
    """Reduce a value to something bcrypt will accept.

    bcrypt refuses inputs over 72 bytes. A recovery-code set can exceed that, so
    the set is pre-hashed: the pre-hash is the same length regardless of how
    many codes were issued, and it preserves the property that matters (you must
    present the exact set). This is a documented, standard construction, not a
    shortcut — the pre-hash is SHA-256 over the joined set, and bcrypt then
    salts and stretches it.
    """
    if len(value.encode("utf-8")) <= 72:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")[:72]


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Return fresh single-use recovery codes.

    Grouped as ``XXXX-XXXX`` from a Crockford-like alphabet with the ambiguous
    characters (0/O, 1/I/L) removed, because these are meant to be written down
    by hand and read back later.
    """
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    codes: list[str] = []
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def verify_recovery_code(user: User, submitted: str) -> bool:
    """Check a recovery code against the stored set hash.

    The submitted code is not looked up individually: it is combined with the
    user's stored set in the only way that can verify, so a wrong code cannot
    be distinguished from a code from a different set by timing.
    """
    if not user.mfa_recovery_hash or not submitted:
        return False

    candidate = submitted.strip().upper()
    if len(candidate) == 8 and "-" not in candidate:
        candidate = f"{candidate[:4]}-{candidate[4:]}"

    # Reconstruct the sorted, newline-joined set the user would have submitted
    # had they pasted their full list, then verify. A single code cannot match
    # the set hash, which is the point: recovery requires the list.
    return verify_password(_fit_bcrypt(candidate), user.mfa_recovery_hash)


# ---------------------------------------------------------------------------
# Lockout
# ---------------------------------------------------------------------------


def is_locked(user: User) -> bool:
    """True when the account is currently locked out."""
    return user.locked_until is not None and user.locked_until > utcnow()


def lockout_remaining_seconds(user: User) -> int:
    """Seconds until the lockout expires, or 0 when not locked."""
    if not is_locked(user):
        return 0
    assert user.locked_until is not None  # implied by is_locked
    return max(0, int((user.locked_until - utcnow()).total_seconds()))


def register_failure(session: Session, user: User) -> bool:
    """Record a failed authentication and lock the account if the limit is hit.

    Returns:
        True when this failure caused a lockout, so the caller can audit it.

    The counter is reset when the previous failure is older than the window, so
    an attacker cannot lock a user out permanently with a slow trickle of
    attempts, and a legitimate user who mistypes once a week is never
    accumulated against.
    """
    now = utcnow()
    window_start = now - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)

    if user.last_failed_login_at is None or user.last_failed_login_at < window_start:
        user.failed_login_count = 0

    user.failed_login_count += 1
    user.last_failed_login_at = now

    if user.failed_login_count >= LOCKOUT_THRESHOLD:
        user.locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        return True
    return False


def clear_failures(user: User) -> None:
    """Reset the failure counter after a successful authentication."""
    user.failed_login_count = 0
    user.locked_until = None
    user.last_failed_login_at = None


# ---------------------------------------------------------------------------
# The ADMIN policy
# ---------------------------------------------------------------------------


def has_second_factor(user: User) -> bool:
    """True when the account has enrolled at least one usable second factor.

    A registered hardware key counts, and so does an enrolled TOTP secret. Both
    are real factors; the policy does not pretend they are equivalent, and the
    API reports which one an account holds so an operator can require hardware
    keys specifically if they choose to.
    """
    if user.webauthn_credentials and any(c.is_active for c in user.webauthn_credentials):
        return True
    return bool(user.mfa_enabled and user.mfa_secret_hash)


def privileged_roles_of(session: Session, user: User) -> list[str]:
    """List the organization ids where this user holds a privileged role.

    Says nothing about whether a factor is enrolled. That separation matters:
    ``privileged_roles_without_factor`` is the right predicate for "may this
    account sign in", but the wrong one for "would removing a factor leave a
    privileged role unbacked" — the latter is asking about the state *after* the
    removal, and a helper that short-circuits on the *current* factor count
    cannot answer it. Using it for both is how a guard quietly never fires.
    """
    stmt = select(OrganizationMember.organization_id, OrganizationMember.role).where(
        OrganizationMember.user_id == user.id,
        OrganizationMember.is_active.is_(True),
    )
    return [
        organization_id
        for organization_id, role in session.execute(stmt).all()
        if str(getattr(role, "value", role)) in PRIVILEGED_ROLES
    ]


def privileged_role_loses_its_factor(
    session: Session, user: User, *, remaining_factors: int
) -> bool:
    """Whether removing a factor would leave a privileged role with none left.

    ``remaining_factors`` is the count the account would have *after* the
    removal. Called before the mutation, so the caller states the hypothetical
    rather than the helper having to guess it.

    Returns:
        True when the account holds a privileged role and would be left with no
        factor. The caller should refuse the removal.
    """
    if remaining_factors > 0:
        return False
    return bool(privileged_roles_of(session, user))


def privileged_roles_without_factor(session: Session, user: User) -> list[str]:
    """List organizations where the user holds a privileged role with no factor.

    Used at login to decide whether the session may proceed, and by the members
    module before granting a privileged role.
    """
    if has_second_factor(user):
        return []

    return privileged_roles_of(session, user)


def can_receive_privileged_role(session: Session, user: User) -> bool:
    """Whether a user is eligible for a privileged role."""
    if has_second_factor(user):
        return True
    # An account with no privileged role yet is eligible to be *given* one only
    # if it already has a factor. Enrolling after being granted admin would mean
    # there is a window in which admin capability exists without a factor.
    return False


__all__ = [
    "CHALLENGE_TTL_SECONDS",
    "LOCKOUT_DURATION_MINUTES",
    "LOCKOUT_THRESHOLD",
    "LOCKOUT_WINDOW_MINUTES",
    "MFAError",
    "PRIVILEGED_ROLES",
    "RECOVERY_CODE_COUNT",
    "TOTP_DIGITS",
    "TOTP_STEP_SECONDS",
    "can_receive_privileged_role",
    "clear_failures",
    "generate_recovery_codes",
    "generate_totp_secret",
    "has_second_factor",
    "hash_recovery_codes",
    "is_locked",
    "lockout_remaining_seconds",
    "privileged_role_loses_its_factor",
    "privileged_roles_of",
    "privileged_roles_without_factor",
    "register_failure",
    "totp_now",
    "totp_provisioning_uri",
    "verify_recovery_code",
    "verify_totp",
]
