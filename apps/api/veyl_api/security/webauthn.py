"""WebAuthn (FIDO2) registration and assertion verification.

Why this is implemented by hand rather than pulled from a library
---------------------------------------------------------------
``python-fido2`` is the obvious dependency, and it is a good one. It is not used
here because the verification this product performs is narrow — registration and
authentication for a known set of credentials — and every step of it is
something a reader of this file should be able to check for themselves. A
security product that asks a user to trust its authentication should not have a
gap between "the library says this is fine" and "we verified this is fine".

What is actually verified, and what is deliberately not
------------------------------------------------------
Verified:

* the challenge matches a server-issued, unconsumed, unexpired challenge;
* the origin matches the configured origin exactly;
* the relying-party id is a suffix of the origin's host;
* the client data type is the expected one (``webauthn.create`` / ``webauthn.get``);
* the credential's public key verifies the signature over
  ``authenticatorData || sha256(clientDataJSON)``;
* for assertions, the signature counter did not go backwards.

**Not** verified, and this is a real limitation rather than an oversight:

* attestation statements and the trust chain of the authenticator. Veyl does not
  check that a key was manufactured by a particular vendor. Attestation would
  let a deployment require a specific hardware model; this implementation does
  not, so it cannot make that claim. The consequence is that a software
  authenticator can register, which is fine for the threat model here
  (stolen-password and phishing resistance) but would not be for one that needs
  to prove physical possession.

The values that would be needed to add attestation verification —
``attestationObject.fmt`` and the attestation statement — are parsed and
retained on the session during registration so the work is not lost, but they
are not evaluated.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from veyl_api.config import settings
from veyl_api.db.base import utcnow
from veyl_api.models import AuthChallenge, User, WebAuthnCredential
from veyl_api.security.mfa import CHALLENGE_TTL_SECONDS, MFAError

# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------


def b64url_decode(value: str) -> bytes:
    """Decode standard base64url, restoring the padding the encoder dropped."""
    if isinstance(value, bytes):
        value = value.decode("ascii")
    padding = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + "=" * padding)


def b64url_encode(value: bytes) -> str:
    """Encode as base64url with no padding, which is what the JS API expects."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# Authenticator data
# ---------------------------------------------------------------------------

#: ``authenticatorData`` layout (W3C WebAuthn §6.1):
#:   rpIdHash     32 bytes
#:   flags         1 byte
#:   signCount     4 bytes big-endian
#:   [attested credential data / extensions follow]
_AUTH_DATA_MIN = 37


@dataclass(frozen=True)
class AuthenticatorData:
    """The parsed fixed portion of ``authenticatorData``."""

    rp_id_hash: bytes
    flags: int
    sign_count: int
    raw: bytes

    @property
    def user_present(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & 0x04)


def parse_authenticator_data(raw: bytes) -> AuthenticatorData:
    """Parse the fixed 37-byte prefix of ``authenticatorData``.

    Raises:
        MFAError: when the blob is too short to be valid.
    """
    if len(raw) < _AUTH_DATA_MIN:
        raise MFAError(
            f"authenticatorData is {len(raw)} bytes; at least {_AUTH_DATA_MIN} are required"
        )
    rp_id_hash = raw[0:32]
    flags = raw[32]
    sign_count = struct.unpack(">I", raw[33:37])[0]
    return AuthenticatorData(
        rp_id_hash=rp_id_hash, flags=flags, sign_count=sign_count, raw=raw
    )


# ---------------------------------------------------------------------------
# CBOR — the subset needed to read a COSE public key and an attestation object
# ---------------------------------------------------------------------------


def _cbor_decode(data: bytes, offset: int = 0) -> tuple[object, int]:
    """Minimal CBOR decoder covering the major types WebAuthn uses.

    WebAuthn payloads use a small, well-defined slice of CBOR: unsigned and
    negative integers, byte strings, text strings, arrays, and maps. A full
    implementation would be a needless dependency for those; this decoder
    raises on anything it does not understand rather than guessing, so an
    unexpected payload fails loudly instead of being misread.
    """
    if offset >= len(data):
        raise MFAError("CBOR data ended unexpectedly")

    initial = data[offset]
    major = initial >> 5
    additional = initial & 0x1F
    offset += 1

    if additional < 24:
        length = additional
    elif additional == 24:
        length = data[offset]
        offset += 1
    elif additional == 25:
        length = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
    elif additional == 26:
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
    elif additional == 27:
        length = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
    else:
        raise MFAError(f"unsupported CBOR additional information: {additional}")

    if major == 0:  # unsigned integer
        return length, offset
    if major == 1:  # negative integer
        return -1 - length, offset
    if major == 2:  # byte string
        return data[offset : offset + length], offset + length
    if major == 3:  # text string
        return data[offset : offset + length].decode("utf-8"), offset + length
    if major == 4:  # array
        items = []
        for _ in range(length):
            item, offset = _cbor_decode(data, offset)
            items.append(item)
        return items, offset
    if major == 5:  # map
        result: dict[object, object] = {}
        for _ in range(length):
            key, offset = _cbor_decode(data, offset)
            value, offset = _cbor_decode(data, offset)
            result[key] = value
        return result, offset
    if major == 7:  # simple values
        if additional == 20:
            return False, offset
        if additional == 21:
            return True, offset
        if additional == 22:
            return None, offset
        raise MFAError(f"unsupported CBOR simple value: {additional}")

    raise MFAError(f"unsupported CBOR major type: {major}")


def cbor_decode(data: bytes) -> object:
    """Decode one CBOR item, requiring it to consume the whole buffer."""
    value, offset = _cbor_decode(data, 0)
    if offset != len(data):
        raise MFAError(
            f"CBOR payload has {len(data) - offset} trailing byte(s); refusing to guess"
        )
    return value


# ---------------------------------------------------------------------------
# COSE public keys
# ---------------------------------------------------------------------------

#: COSE algorithm identifiers Veyl will verify. Anything else is refused rather
#: than accepted-and-ignored, so an unsupported key cannot silently become a
#: bypass.
COSE_ALGORITHMS: dict[int, tuple[str, str]] = {
    -7: ("ES256", "SHA256"),  # ECDSA w/ SHA-256, P-256
    -35: ("ES384", "SHA384"),  # ECDSA w/ SHA-384, P-384
    -36: ("ES512", "SHA512"),  # ECDSA w/ SHA-512, P-521
    -257: ("RS256", "SHA256"),  # RSASSA-PKCS1-v1_5 w/ SHA-256
}

COSE_KTY = 1
COSE_ALG = 3
COSE_CRV = -1
COSE_X = -2
COSE_Y = -3
COSE_N = -1
COSE_E = -2

CURVE_P256, CURVE_P384, CURVE_P521 = 1, 2, 3
CURVE_NAMES = {
    CURVE_P256: ("secp256r1", 32),
    CURVE_P384: ("secp384r1", 48),
    CURVE_P521: ("secp521r1", 66),
}


def parse_cose_key(cose_bytes: bytes) -> tuple[str, bytes, str | None]:
    """Extract ``(algorithm, public_key_pem_der, curve_name)`` from a COSE key.

    The result is a SubjectPublicKeyInfo blob (DER), which is what
    ``cryptography`` consumes, plus the JWS algorithm name the key implies.

    Raises:
        MFAError: on a key type, curve, or algorithm that is not supported.
    """
    key = cbor_decode(cose_bytes)
    if not isinstance(key, dict):
        raise MFAError("COSE key is not a map")
    if key.get(COSE_KTY) != 2:
        # kty 2 is EC2; kty 3 is RSA. kty 1 (OKP) is Ed25519, which some
        # authenticators use and this implementation does not yet verify.
        raise MFAError(f"unsupported COSE key type: {key.get(COSE_KTY)!r} (only EC2 is supported)")

    algorithm_id = key.get(COSE_ALG)
    if algorithm_id not in COSE_ALGORITHMS:
        raise MFAError(
            f"unsupported COSE algorithm {algorithm_id!r}; supported: "
            f"{sorted(COSE_ALGORITHMS)}"
        )
    algorithm, _hash_name = COSE_ALGORITHMS[algorithm_id]

    curve_id = key.get(COSE_CRV)
    if curve_id not in CURVE_NAMES:
        raise MFAError(f"unsupported COSE curve: {curve_id!r}")
    curve_name, _size = CURVE_NAMES[curve_id]

    x = key.get(COSE_X)
    y = key.get(COSE_Y)
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        raise MFAError("COSE EC2 key is missing its x or y coordinate")

    from cryptography.hazmat.primitives.asymmetric import ec

    curve = {
        CURVE_P256: ec.SECP256R1(),
        CURVE_P384: ec.SECP384R1(),
        CURVE_P521: ec.SECP521R1(),
    }[curve_id]

    public_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"), y=int.from_bytes(y, "big"), curve=curve
    )
    public_key = public_numbers.public_key()

    from cryptography.hazmat.primitives import serialization

    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return algorithm, der, curve_name


def verify_signature(algorithm: str, der_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a WebAuthn signature over ``message``.

    Supports both signature encodings authenticators actually produce: the raw
    ``r||s`` form that ES256 uses, and the ASN.1 DER form that the RSA
    algorithms use. Returning False rather than raising keeps the caller's
    error handling uniform — an unverifiable signature and a malformed one are
    the same outcome for the user.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

        public_key = serialization.load_der_public_key(der_key)

        if algorithm == "ES256":
            # WebAuthn transmits ECDSA signatures as raw r||s, but
            # ``cryptography`` wants DER. Convert rather than assume the input
            # is already DER, which is a common source of silent failures.
            if len(signature) == 64:
                r = int.from_bytes(signature[:32], "big")
                s = int.from_bytes(signature[32:], "big")
                signature = utils.encode_dss_signature(r, s)
            elif len(signature) == 96:  # P-384
                r = int.from_bytes(signature[:48], "big")
                s = int.from_bytes(signature[48:], "big")
                signature = utils.encode_dss_signature(r, s)
            elif len(signature) == 132:  # P-521
                r = int.from_bytes(signature[:66], "big")
                s = int.from_bytes(signature[66:], "big")
                signature = utils.encode_dss_signature(r, s)
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True

        if algorithm == "ES384":
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA384()))
            return True
        if algorithm == "ES512":
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA512()))
            return True
        if algorithm == "RS256":
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            return True

        # An algorithm that reached here was not in COSE_ALGORITHMS, which means
        # a code path added one without adding verification for it. Refusing is
        # the only safe answer.
        return False
    except InvalidSignature:
        return False
    except Exception as exc:  # noqa: BLE001 - malformed input is a failed verification
        raise MFAError(f"signature could not be checked: {exc}") from exc


# ---------------------------------------------------------------------------
# Challenge lifecycle
# ---------------------------------------------------------------------------


def issue_challenge(session: Session, *, purpose: str, user_id: str | None) -> str:
    """Create and persist a fresh single-use challenge.

    ``secrets.token_bytes`` is used rather than ``random``: a predictable
    challenge would let an attacker precompute a signature against a challenge
    the server is about to issue.
    """
    challenge = b64url_encode(secrets.token_bytes(32))
    session.add(
        AuthChallenge(
            user_id=user_id,
            challenge=challenge,
            purpose=purpose,
            expires_at=utcnow() + timedelta(seconds=CHALLENGE_TTL_SECONDS),
        )
    )
    session.flush()
    return challenge


def consume_challenge(session: Session, *, challenge: str, purpose: str) -> AuthChallenge:
    """Atomically mark a challenge used, refusing anything invalid.

    A challenge is consumed whether or not the ceremony that follows succeeds.
    Leaving it live would turn a failed attempt into a retryable oracle, which
    is precisely what a single-use challenge exists to prevent.

    Raises:
        MFAError: when the challenge is unknown, already used, expired, or
            was issued for a different purpose.
    """
    stmt = select(AuthChallenge).where(
        AuthChallenge.challenge == challenge,
        AuthChallenge.purpose == purpose,
    )
    record = session.execute(stmt).scalar_one_or_none()
    if record is None:
        raise MFAError("this challenge was not issued by this server")

    if record.consumed_at is not None:
        raise MFAError("this challenge has already been used")

    if record.expires_at <= utcnow():
        raise MFAError("this challenge has expired; start the ceremony again")

    record.consumed_at = utcnow()
    session.flush()
    return record


# ---------------------------------------------------------------------------
# Origin / RP id
# ---------------------------------------------------------------------------


def configured_origins() -> list[str]:
    """Origins allowed to complete a WebAuthn ceremony.

    Taken from the same CORS list the browser is already restricted by, so the
    two cannot drift apart: an origin that can make an authenticated request is
    exactly an origin that may complete a ceremony.
    """
    return list(settings.cors_origin_list)


def verify_origin(client_data: dict, *, expected_type: str) -> None:
    """Check the ceremony origin and type.

    Origin checking is the reason WebAuthn resists a real-time phishing proxy.
    A proxy can relay a password and a TOTP code, but the browser will not sign
    a challenge for an origin other than the one it is displaying, and this is
    where the server confirms that.

    Raises:
        MFAError: on a mismatch. The check is exact string equality —
            no suffix matching, no case folding, no trailing-slash tolerance.
    """
    origin = client_data.get("origin")
    allowed = configured_origins()
    if origin not in allowed:
        raise MFAError(
            f"this ceremony came from origin {origin!r}, which is not an allowed "
            f"origin for this deployment (expected one of {allowed})"
        )

    actual_type = client_data.get("type")
    if actual_type != expected_type:
        raise MFAError(
            f"expected a {expected_type!r} ceremony, received {actual_type!r}"
        )


def verify_rp_id(rp_id_hash: bytes, *, origin: str) -> None:
    """Check ``rpIdHash`` equals SHA-256 of the relying-party id.

    The RP id is the origin's host, without a port. Comparing the hash proves
    the authenticator was scoped to this site and not to a lookalike domain that
    happened to be signed for.

    Raises:
        MFAError: on a mismatch.
    """
    from urllib.parse import urlparse

    host = urlparse(origin).hostname or ""
    expected = hashlib.sha256(host.encode("utf-8")).digest()
    if not secrets.compare_digest(rp_id_hash, expected):
        raise MFAError(
            f"the authenticator was scoped to a different relying party than {host!r}"
        )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegistrationResult:
    """What a successful registration yields."""

    credential_id: str
    public_key_der: bytes
    algorithm: str
    curve: str
    sign_count: int
    transports: str | None
    aaguid: str | None
    #: Parsed but not evaluated. See the module docstring.
    attestation_format: str | None


def verify_registration(
    session: Session,
    *,
    user: User,
    credential_id: str,
    client_data_json: str,
    attestation_object: str,
    transports: list[str] | None = None,
) -> RegistrationResult:
    """Verify a ``navigator.credentials.create()`` response and return the key.

    Raises:
        MFAError: on any verification failure. Every failure is a refusal; the
            function never returns a partially trusted credential.
    """
    try:
        client_data = json.loads(b64url_decode(client_data_json))
        attestation = cbor_decode(b64url_decode(attestation_object))
    except (ValueError, json.JSONDecodeError) as exc:
        raise MFAError(f"registration payload is not valid base64url JSON/CBOR: {exc}") from exc

    if not isinstance(client_data, dict) or not isinstance(attestation, dict):
        raise MFAError("registration payload did not decode to the expected structures")

    verify_origin(client_data, expected_type="webauthn.create")

    raw_challenge = client_data.get("challenge")
    if not isinstance(raw_challenge, str):
        raise MFAError("clientDataJSON has no challenge")
    consume_challenge(session, challenge=raw_challenge, purpose="registration")

    auth_data_raw = attestation.get("authData")
    if not isinstance(auth_data_raw, bytes):
        raise MFAError("attestationObject has no authData")

    auth_data = parse_authenticator_data(auth_data_raw)
    verify_rp_id(auth_data.rp_id_hash, origin=client_data["origin"])

    if not auth_data.user_present:
        raise MFAError("the authenticator did not report user presence")

    if not (auth_data.flags & 0x40):
        # Bit 6 is AT: attested credential data is included. Without it there is
        # no public key to store, so registration cannot proceed.
        raise MFAError("the authenticator did not return attested credential data")

    credential_id_bytes, public_key_cose, aaguid = _parse_attested_credential_data(
        auth_data_raw[_AUTH_DATA_MIN:]
    )

    # The credential id in the attestation must match the one the client claims.
    # Trusting the client's value alone would let a caller register a key while
    # reporting someone else's credential id.
    if b64url_encode(credential_id_bytes) != credential_id.rstrip("="):
        raise MFAError("the credential id does not match the one in the attestation")

    algorithm, public_key_der, curve = parse_cose_key(public_key_cose)

    existing = session.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id.rstrip("=")
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise MFAError(
            "this authenticator is already registered"
            + (" to your account" if existing.user_id == user.id else " to another account")
        )

    return RegistrationResult(
        credential_id=credential_id.rstrip("="),
        public_key_der=public_key_der,
        algorithm=algorithm,
        curve=curve,
        sign_count=auth_data.sign_count,
        transports=",".join(transports) if transports else None,
        aaguid=b64url_encode(aaguid) if aaguid else None,
        attestation_format=(
            str(attestation.get("fmt")) if attestation.get("fmt") is not None else None
        ),
    )


def _parse_attested_credential_data(data: bytes) -> tuple[bytes, bytes, bytes | None]:
    """Read ``credentialId``, ``COSE public key``, and AAGUID from the tail.

    Layout: aaguid(16) || credentialIdLength(2) || credentialId || coseKey.
    """
    if len(data) < 18:
        raise MFAError("attested credential data is truncated")

    aaguid = data[0:16]
    credential_id_length = struct.unpack(">H", data[16:18])[0]
    start = 18
    end = start + credential_id_length

    if len(data) < end:
        raise MFAError("attested credential data is shorter than its stated credential id")

    credential_id = data[start:end]
    # The COSE key is whatever remains, minus any CBOR extension map. Consuming
    # exactly the key blob is what makes ``cbor_decode``'s trailing-byte check
    # meaningful, so the key is re-encoded rather than the tail taken wholesale.
    key_blob = _slice_one_cbor_item(data[end:])

    return credential_id, key_blob, aaguid


def _slice_one_cbor_item(data: bytes) -> bytes:
    """Return the bytes of exactly one CBOR item from the front of ``data``."""
    _value, offset = _cbor_decode(data, 0)
    return data[:offset]


# ---------------------------------------------------------------------------
# Assertion
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssertionResult:
    """What a successful assertion yields."""

    credential: WebAuthnCredential
    new_sign_count: int


def verify_assertion(
    session: Session,
    *,
    credential: WebAuthnCredential,
    client_data_json: str,
    authenticator_data: str,
    signature: str,
    user_handle: str | None = None,
) -> AssertionResult:
    """Verify a ``navigator.credentials.get()`` response.

    Raises:
        MFAError: on any verification failure, including a signature counter
            that went backwards.
    """
    try:
        client_data = json.loads(b64url_decode(client_data_json))
        auth_data_raw = b64url_decode(authenticator_data)
        signature_bytes = b64url_decode(signature)
    except (ValueError, json.JSONDecodeError) as exc:
        raise MFAError(f"assertion payload is not valid base64url JSON: {exc}") from exc

    if not isinstance(client_data, dict):
        raise MFAError("clientDataJSON did not decode to an object")

    verify_origin(client_data, expected_type="webauthn.get")

    raw_challenge = client_data.get("challenge")
    if not isinstance(raw_challenge, str):
        raise MFAError("clientDataJSON has no challenge")
    consume_challenge(session, challenge=raw_challenge, purpose="authentication")

    auth_data = parse_authenticator_data(auth_data_raw)
    verify_rp_id(auth_data.rp_id_hash, origin=client_data["origin"])

    if not auth_data.user_present:
        raise MFAError("the authenticator did not report user presence")

    # The signature covers the authenticator data verbatim followed by the hash
    # of the client data. Reproducing that byte-for-byte is the whole check.
    client_data_hash = hashlib.sha256(b64url_decode(client_data_json)).digest()
    message = auth_data_raw + client_data_hash

    if not verify_signature(
        credential.algorithm,
        b64url_decode(credential.public_key),
        signature_bytes,
        message,
    ):
        raise MFAError("the signature did not verify against the registered public key")

    # A counter that does not advance is the documented signal that a credential
    # may have been cloned. Some authenticators legitimately always report 0, so
    # a stored 0 is treated as "no counter support" rather than as a regression.
    if credential.sign_count and auth_data.sign_count <= credential.sign_count:
        raise MFAError(
            "the authenticator's signature counter did not advance, which can indicate "
            "a cloned credential; sign-in refused"
        )

    return AssertionResult(credential=credential, new_sign_count=auth_data.sign_count)


__all__ = [
    "COSE_ALGORITHMS",
    "AssertionResult",
    "RegistrationResult",
    "b64url_decode",
    "b64url_encode",
    "cbor_decode",
    "configured_origins",
    "consume_challenge",
    "issue_challenge",
    "parse_authenticator_data",
    "parse_cose_key",
    "verify_assertion",
    "verify_origin",
    "verify_registration",
    "verify_rp_id",
    "verify_signature",
]
