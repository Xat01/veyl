"""Authentication primitives: password hashing and JWT issuance.

Deliberate choices:

* **bcrypt** for passwords. Cost is the library default; we never roll our own
  KDF and never store anything reversible.
* **Short-lived access tokens** plus a longer refresh token, so a stolen access
  token has a bounded blast radius.
* The JWT carries only ``sub``, ``org``, and ``role``. Authorization data is
  re-read from the database on every request rather than trusted from the
  token, so revoking a membership takes effect immediately.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
from passlib.context import CryptContext

from veyl_api.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"

TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired, or has a bad signature."""


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash a plaintext password."""
    # bcrypt silently truncates at 72 bytes; reject rather than accept a
    # password whose security depends only on its first 72 bytes.
    if len(password.encode("utf-8")) > 72:
        raise ValueError("password exceeds 72 bytes; choose a shorter passphrase")
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time-ish verification via the KDF. Returns False on any error."""
    try:
        return pwd_context.verify(password, password_hash)
    except (ValueError, TypeError):
        return False


def validate_password_strength(password: str) -> list[str]:
    """Return a list of unmet requirements. Empty list means acceptable."""
    problems: list[str] = []
    if len(password) < 12:
        problems.append("must be at least 12 characters")
    if len(password.encode("utf-8")) > 72:
        problems.append("must be at most 72 bytes")
    if not any(c.islower() for c in password):
        problems.append("must contain a lowercase letter")
    if not any(c.isupper() for c in password):
        problems.append("must contain an uppercase letter")
    if not any(c.isdigit() for c in password):
        problems.append("must contain a digit")
    if not any(not c.isalnum() for c in password):
        problems.append("must contain a symbol")
    if password.lower() in _COMMON_PASSWORDS:
        problems.append("appears in the common-password blocklist")
    return problems


_COMMON_PASSWORDS = frozenset(
    {
        "password1234",
        "administrator",
        "changeme1234",
        "qwerty123456",
        "letmein12345",
        "welcome12345",
        "Password123!",
    }
)


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 0


def create_token(
    *,
    user_id: str,
    organization_id: str | None,
    role: str | None,
    token_type: TokenType = "access",
    expires_delta: timedelta | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Mint a signed JWT."""
    now = datetime.now(timezone.utc)
    if expires_delta is None:
        expires_delta = (
            timedelta(minutes=settings.access_token_ttl_minutes)
            if token_type == "access"
            else timedelta(days=settings.refresh_token_ttl_days)
        )
    payload: dict[str, Any] = {
        "sub": user_id,
        "org": organization_id,
        "role": role,
        "type": token_type,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def create_token_pair(
    *, user_id: str, organization_id: str | None, role: str | None
) -> TokenPair:
    """Mint an access/refresh pair for a user's active organization."""
    return TokenPair(
        access_token=create_token(
            user_id=user_id, organization_id=organization_id, role=role, token_type="access"
        ),
        refresh_token=create_token(
            user_id=user_id, organization_id=organization_id, role=role, token_type="refresh"
        ),
        expires_in=settings.access_token_ttl_minutes * 60,
    )


def decode_token(token: str, *, expected_type: TokenType | None = None) -> dict[str, Any]:
    """Verify and decode a JWT.

    Raises:
        TokenError: on any validation failure.
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError(f"invalid token: {exc}") from exc

    if expected_type is not None and payload.get("type") != expected_type:
        raise TokenError(f"expected a {expected_type} token, got {payload.get('type')!r}")

    return payload


# ---------------------------------------------------------------------------
# API keys (for machine-to-machine scan submission)
# ---------------------------------------------------------------------------


def generate_api_key() -> tuple[str, str]:
    """Return ``(plaintext, hash)`` for a new API key.

    Only the hash is stored. The plaintext is shown once at creation time.
    """
    plaintext = "veyl_" + secrets.token_urlsafe(32)
    return plaintext, hash_api_key(plaintext)


def hash_api_key(plaintext: str) -> str:
    """Hash an API key with the deployment secret as a pepper."""
    digest = hashlib.sha256()
    digest.update(plaintext.encode("utf-8"))
    digest.update(b"|")
    digest.update(settings.secret_key.encode("utf-8"))
    return digest.hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings without leaking length-independent timing."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
