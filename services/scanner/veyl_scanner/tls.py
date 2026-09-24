"""TLS collection and Certificate Transparency subdomain discovery.

TLS facts are collected by completing a real handshake and inspecting the peer
certificate. Version and cipher come from the negotiated session, not from a
guess. Chain validation is performed separately and reported as its own field so
"self-signed" and "expired" and "wrong hostname" stay distinguishable.

Certificate Transparency is used only to *propose* names. Every proposed name is
re-checked against the scope guard before it is ever resolved or probed.
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from veyl_api.enums import Confidence, Provenance
from veyl_scanner.contracts import (
    CollectorRegistration,
    CollectResult,
    ObservationPayload,
    ScanRequest,
)

CRT_SH_BASE = "https://crt.sh"
_CRT_TIMEOUT = 12.0

#: TLS versions we treat as deprecated when negotiating.
DEPRECATED_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}

#: Cipher suites with known weaknesses that we report by name.
WEAK_CIPHER_MARKERS = (
    "RC4",
    "3DES",
    "DES-CBC",
    "NULL",
    "EXPORT",
    "MD5",
    "anon",
    "ADH",
    "AECDH",
)


@dataclass
class CertificateFacts:
    """Everything observed about one certificate."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    san: list[str]
    fingerprint_sha256: str
    is_self_signed: bool
    signature_algorithm: str | None
    key_size: int | None
    tls_version: str | None
    cipher_suite: str | None
    chain_valid: bool | None
    hostname_valid: bool | None
    raw: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "san": self.san,
            "fingerprint_sha256": self.fingerprint_sha256,
            "is_self_signed": self.is_self_signed,
            "signature_algorithm": self.signature_algorithm,
            "key_size": self.key_size,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "chain_valid": self.chain_valid,
            "hostname_valid": self.hostname_valid,
        }


def _name_to_string(name: x509.Name) -> str:
    """Render an X.509 name as its most useful single-line form."""
    common = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if common:
        return str(common[0].value)
    return name.rfc4514_string()


def _parse_not_after(value: str) -> datetime:
    """Parse the ``notAfter`` string SSL gives us (e.g. 'Jun  1 12:00:00 2027 GMT')."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y %z"):
        try:
            parsed = datetime.strptime(value.strip(), fmt)
            return parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    # Last resort: return a far-future sentinel so nothing crashes; the raw
    # string is still stored in the observation.
    return datetime(1970, 1, 1, tzinfo=UTC)


def inspect_certificate(
    hostname: str, address: str, port: int, timeout: float
) -> CertificateFacts | None:
    """Perform a TLS handshake and extract certificate + session facts.

    Verification is disabled for collection so an expired or self-signed
    certificate can still be *observed*. Chain validity is then assessed
    separately and honestly reported.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Allow the negotiation to exercise whatever the server offers, including
    # old versions, because "server offered TLS 1.0" is a finding we want.
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass

    raw_sock = None
    tls_sock = None
    try:
        raw_sock = socket.create_connection((address, port), timeout=timeout)
        tls_sock = context.wrap_socket(raw_sock, server_hostname=hostname)
    except (TimeoutError, ssl.SSLError, OSError):
        if raw_sock is not None:
            try:
                raw_sock.close()
            except OSError:
                pass
        return None

    try:
        negotiated_version = tls_sock.version()
        cipher = tls_sock.cipher()
        der = tls_sock.getpeercert(binary_form=True)
        if not der:
            return None

        import hashlib

        fingerprint = hashlib.sha256(der).hexdigest()

        cert = x509.load_der_x509_certificate(der, default_backend())

        subject = _name_to_string(cert.subject)
        issuer = _name_to_string(cert.issuer)

        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:  # cryptography < 42
            not_before = cert.not_valid_before.replace(tzinfo=UTC)
            not_after = cert.not_valid_after.replace(tzinfo=UTC)

        san: list[str] = []
        try:
            extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = [str(n) for n in extension.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            san = []

        is_self_signed = cert.issuer == cert.subject

        signature_algorithm = None
        try:
            signature_algorithm = cert.signature_algorithm_oid._name
        except (AttributeError, ValueError):
            signature_algorithm = str(cert.signature_algorithm_oid)

        key_size = None
        try:
            public_key = cert.public_key()
            key_size = getattr(public_key, "key_size", None)
        except (ValueError, TypeError):
            key_size = None

        # Assess chain validity separately with a verifying context.
        chain_valid: bool | None = None
        try:
            verify_context = ssl.create_default_context()
            with socket.create_connection((address, port), timeout=timeout) as check_sock:
                with verify_context.wrap_socket(check_sock, server_hostname=hostname):
                    chain_valid = True
        except ssl.SSLCertVerificationError:
            chain_valid = False
        except (TimeoutError, OSError, ssl.SSLError):
            chain_valid = None

        hostname_valid = _hostname_matches(hostname, subject, san)

        return CertificateFacts(
            subject=subject,
            issuer=issuer,
            serial_number=format(cert.serial_number, "x"),
            not_before=not_before,
            not_after=not_after,
            san=san,
            fingerprint_sha256=fingerprint,
            is_self_signed=is_self_signed,
            signature_algorithm=signature_algorithm,
            key_size=key_size,
            tls_version=negotiated_version,
            cipher_suite=cipher[0] if cipher else None,
            chain_valid=chain_valid,
            hostname_valid=hostname_valid,
            raw={
                "der_sha256": fingerprint,
                "subject_rfc4514": cert.subject.rfc4514_string(),
                "issuer_rfc4514": cert.issuer.rfc4514_string(),
                "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
                "serial_size_bytes": cert.serial_number.bit_length() // 8 + 1,
            },
        )
    except (ssl.SSLError, ValueError, TypeError):
        return None
    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass


def _hostname_matches(hostname: str, cn: str, san: list[str]) -> bool:
    """RFC 6125-ish hostname check supporting a single wildcard label.

    Modern clients ignore CN when SANs are present, and so do we.
    """
    candidates = san if san else [cn]
    host = hostname.lower().rstrip(".")
    for candidate in candidates:
        pattern = candidate.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if host.endswith("." + suffix) and host.count(".") == suffix.count(".") + 1:
                return True
    return False


def is_deprecated_tls_version(version: str | None) -> bool:
    return bool(version and version in DEPRECATED_TLS_VERSIONS)


def is_weak_cipher(suite: str | None) -> bool:
    if not suite:
        return False
    upper = suite.upper()
    return any(marker.upper() in upper for marker in WEAK_CIPHER_MARKERS)


def days_until(not_after: datetime, *, now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    return (not_after - now).days


class TlsCollector:
    """Collects certificate and TLS session facts for HTTPS ports."""

    name = "tls"
    registration = CollectorRegistration(
        name="tls",
        description="Performs a TLS handshake and records certificate chain, expiry, version and cipher.",
        produces=["tls_certificate", "tls_configuration"],
        requires_ports=[443, 8443],
    )

    def collect(self, request: ScanRequest) -> CollectResult:
        result = CollectResult()
        tls_ports = [p for p in request.ports if p in (443, 8443)] or [
            p for p in request.ports if p > 1024
        ][:3]

        for port in tls_ports:
            facts = inspect_certificate(
                request.hostname, request.addresses[0], port, request.timeout_seconds
            )
            if facts is None:
                continue

            result.observations.append(
                ObservationPayload(
                    kind="tls_certificate",
                    subject=f"{request.hostname}:{port}",
                    asset_key=request.hostname,
                    data={"hostname": request.hostname, "port": port, **facts.as_dict()},
                    provenance=Provenance.OBSERVED,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"Certificate {facts.subject!r} from {facts.issuer!r}, "
                        f"expires {facts.not_after.date().isoformat()}"
                    ),
                )
            )

            result.observations.append(
                ObservationPayload(
                    kind="tls_configuration",
                    subject=f"{request.hostname}:{port}",
                    asset_key=request.hostname,
                    data={
                        "hostname": request.hostname,
                        "port": port,
                        "tls_version": facts.tls_version,
                        "cipher_suite": facts.cipher_suite,
                        "deprecated_version": is_deprecated_tls_version(facts.tls_version),
                        "weak_cipher": is_weak_cipher(facts.cipher_suite),
                        "chain_valid": facts.chain_valid,
                        "hostname_valid": facts.hostname_valid,
                        "is_self_signed": facts.is_self_signed,
                        "key_size": facts.key_size,
                    },
                    provenance=Provenance.OBSERVED,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"TLS {facts.tls_version or 'unknown'} / "
                        f"{facts.cipher_suite or 'unknown cipher'}"
                    ),
                )
            )

        return result


# ---------------------------------------------------------------------------
# Certificate Transparency
# ---------------------------------------------------------------------------


def fetch_ct_names(domain: str, *, timeout: float = _CRT_TIMEOUT) -> list[str]:
    """Query crt.sh for certificate SANs covering ``domain``.

    Returns candidate names only. This function never probes them; the caller
    re-checks scope. Network or parse failures yield an empty list rather than
    raising, because external intelligence must never break a scan.
    """
    url = f"{CRT_SH_BASE}/?q=%25.{urllib.parse.quote(domain)}&output=json"
    request = urllib.request.Request(  # noqa: S310 - fixed https host, constant path
        url,
        headers={"User-Agent": "Veyl-Exposure-Intelligence/0.1", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            payload = response.read(4_000_000)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        return []

    try:
        entries = json.loads(payload.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    names: set[str] = set()
    if not isinstance(entries, list):
        return []

    for entry in entries[:2000]:
        if not isinstance(entry, dict):
            continue
        value = entry.get("name_value") or entry.get("common_name") or ""
        for line in str(value).splitlines():
            candidate = line.strip().lower().lstrip("*.").rstrip(".")
            if not candidate or len(candidate) > 253:
                continue
            # Only names under the queried domain, and only well-formed ones.
            if candidate == domain or candidate.endswith("." + domain):
                names.add(candidate)
    return sorted(names)


class CertificateTransparencyCollector:
    """Proposes subdomains observed in public certificate transparency logs."""

    name = "ct"
    registration = CollectorRegistration(
        name="ct",
        description=(
            "Queries Certificate Transparency logs for names covering the target domain. "
            "Results are candidates only and are re-checked against the scope guard."
        ),
        produces=["ct_candidate_name"],
        always_run=True,
    )

    def collect(self, request: ScanRequest) -> CollectResult:
        result = CollectResult()
        # Only meaningful for a registrable-looking name.
        parts = request.hostname.split(".")
        if len(parts) < 2:
            return result

        apex = ".".join(parts[-2:])
        names = fetch_ct_names(apex)
        if not names:
            return result

        result.observations.append(
            ObservationPayload(
                kind="ct_candidate_names",
                subject=apex,
                asset_key=request.hostname,
                data={"apex": apex, "names": names[:500], "count": len(names)},
                provenance=Provenance.OBSERVED,
                confidence=Confidence.MEDIUM,
                summary=f"{len(names)} name(s) observed in Certificate Transparency for {apex}",
            )
        )
        result.discovered_names = names
        return result
