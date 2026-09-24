"""SSRF and target-safety validation.

This module is the single choke point through which every outbound network
target must pass before Veyl connects to it. It is intentionally paranoid and
intentionally boring: no clever parsing, no regex-based host matching, no
trusting of DNS.

Threat model recap
------------------
A user supplies a target. That target may be:

* a hostname that resolves to an internal address (DNS rebinding / split-horizon)
* a decimal, octal, or hex-encoded IP that naive parsers miss
* an IPv6 address wrapping an IPv4 loopback (``::ffff:127.0.0.1``)
* a cloud metadata endpoint (``169.254.169.254`` and friends)
* something with a trailing dot, IDN homoglyph, or embedded whitespace

Every one of those must be rejected before a socket is opened. This module
resolves names itself and validates every returned address, then hands the
*resolved addresses* to the caller so the connector dials a vetted IP rather
than re-resolving (which would reopen the rebinding window).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum

from veyl_api.config import METADATA_ADDRESSES, settings

#: Hostnames that must never be resolvable as scan targets.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "kubernetes.default",
    }
)

_BLOCKED_HOSTNAME_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".in-addr.arpa",
    ".ip6.arpa",
    ".cluster.local",
)

#: Only these characters may appear in a hostname Veyl will attempt to resolve.
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?)*$")

#: RFC 1123 label, used for the strict form (no underscores).
_STRICT_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$"
)


class TargetRejectionReason(StrEnum):
    """Why a target was refused. Surfaced verbatim in scan results."""

    EMPTY = "EMPTY"
    MALFORMED = "MALFORMED"
    INVALID_HOSTNAME = "INVALID_HOSTNAME"
    BLOCKED_HOSTNAME = "BLOCKED_HOSTNAME"
    DNS_FAILURE = "DNS_FAILURE"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    PRIVATE = "PRIVATE"
    RESERVED = "RESERVED"
    MULTICAST = "MULTICAST"
    UNSPECIFIED = "UNSPECIFIED"
    METADATA = "METADATA"
    NAT64_EMBEDDED = "NAT64_EMBEDDED"
    PORT_NOT_ALLOWED = "PORT_NOT_ALLOWED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    SCOPE_EXPIRED = "SCOPE_EXPIRED"


@dataclass(frozen=True)
class ValidatedTarget:
    """A target that passed the safety floor."""

    hostname: str
    addresses: tuple[str, ...]
    resolved_via: str = "dns"


@dataclass
class TargetRejection:
    """A target that was refused, with a machine-readable reason."""

    target: str
    reason: TargetRejectionReason
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "target": self.target,
            "reason": self.reason.value,
            "detail": self.detail,
        }


class UnsafeTargetError(ValueError):
    """Raised when a target is refused. Carries the structured rejection."""

    def __init__(self, rejection: TargetRejection) -> None:
        self.rejection = rejection
        super().__init__(f"{rejection.target}: {rejection.reason.value} ({rejection.detail})")


@dataclass
class ValidationResult:
    """Outcome of validating a batch of targets."""

    accepted: list[ValidatedTarget] = field(default_factory=list)
    rejected: list[TargetRejection] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------


def normalize_ip_literal(token: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a host token as an IP literal, including obfuscated forms.

    ``ipaddress`` already handles decimal (``2130706433``), hex (``0x7f000001``),
    and octal-ish integer forms plus IPv6 wrappers. We therefore feed the token
    to it directly *before* any DNS lookup, which is what closes the "numeric
    encoding" bypass class.
    """
    candidate = token.strip().strip("[]")
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass

    # ``ipaddress`` rejects a bare integer string in some Python versions when it
    # contains no dots; handle the unambiguous pure-integer case explicitly.
    if re.fullmatch(r"\d{1,20}", candidate):
        try:
            as_int = int(candidate)
            if 0 <= as_int <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(as_int)
        except ValueError:
            return None
    return None


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Extract an embedded IPv4 address from an IPv6 address, if any.

    Covers ``::ffff:1.2.3.4`` (IPv4-mapped), ``64:ff9b::/96`` (NAT64) and
    ``2002::/16`` (6to4) — all of which are documented SSRF bypass vectors.
    """
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr.sixtofour is not None:
        return addr.sixtofour
    # NAT64 well-known prefix
    if addr in ipaddress.ip_network("64:ff9b::/96") and not addr.is_unspecified:
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


def classify_address(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool | None = None,
) -> TargetRejectionReason | None:
    """Return the reason an address is unsafe, or ``None`` if it is acceptable.

    Order matters: metadata is checked before the broader private range so the
    reason reported to the user is the most specific and most alarming one.
    """
    if allow_private is None:
        allow_private = settings.allow_private_targets

    # Guard the embedded-IPv4 cases first, since an IPv6 wrapper around 127.0.0.1
    # would otherwise slip past the IPv4 checks entirely.
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(addr)
        if embedded is not None:
            embedded_reason = classify_address(embedded, allow_private=allow_private)
            if embedded_reason is not None:
                return embedded_reason
            # Even if the embedded address is acceptable, an IPv6 wrapper is a
            # signature of an attempt to obscure the real destination.
            return TargetRejectionReason.NAT64_EMBEDDED

    if settings.always_block_metadata and addr in METADATA_ADDRESSES:
        return TargetRejectionReason.METADATA

    # 100.64.0.0/10 (carrier-grade NAT) is also used by some clouds for metadata.
    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"):
        if settings.always_block_metadata:
            return TargetRejectionReason.METADATA

    if addr.is_multicast:
        return TargetRejectionReason.MULTICAST
    if addr.is_unspecified:
        return TargetRejectionReason.UNSPECIFIED
    if addr.is_loopback:
        return TargetRejectionReason.LOOPBACK
    if addr.is_link_local:
        return TargetRejectionReason.LINK_LOCAL

    if not allow_private:
        if addr.is_private:
            return TargetRejectionReason.PRIVATE
        if addr.is_reserved:
            return TargetRejectionReason.RESERVED

    return None


# ---------------------------------------------------------------------------
# Hostname validation
# ---------------------------------------------------------------------------


def normalize_hostname(raw: str) -> str:
    """Normalise a hostname for comparison and resolution.

    Applies NFKC to collapse homoglyphs, lowercases, strips a single trailing
    dot (FQDN form) and rejects anything containing control characters. The
    result is *only* used for validation and scope matching; the original is
    never passed to a shell.
    """
    value = unicodedata.normalize("NFKC", raw).strip().lower()
    if value.endswith(".") and value.count(".") >= 1:
        value = value[:-1]
    return value


def validate_hostname_syntax(hostname: str) -> TargetRejection | None:
    """Reject hostnames that are not well-formed DNS names."""
    if not hostname:
        return TargetRejection("", TargetRejectionReason.EMPTY, "no hostname supplied")

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in hostname):
        return TargetRejection(
            hostname, TargetRejectionReason.MALFORMED, "hostname contains control characters"
        )

    # Reject anything that could be interpreted by a shell or URL parser.
    if any(ch in hostname for ch in " \t\r\n/\\?#@\"'`$;|&<>(){}[]*%,"):
        return TargetRejection(
            hostname,
            TargetRejectionReason.MALFORMED,
            "hostname contains characters that are not valid in a DNS name",
        )

    if len(hostname) > 253:
        return TargetRejection(hostname, TargetRejectionReason.MALFORMED, "hostname too long")

    if hostname in _BLOCKED_HOSTNAMES:
        return TargetRejection(
            hostname, TargetRejectionReason.BLOCKED_HOSTNAME, "hostname is on the deny list"
        )

    for suffix in _BLOCKED_HOSTNAME_SUFFIXES:
        if hostname.endswith(suffix):
            return TargetRejection(
                hostname,
                TargetRejectionReason.BLOCKED_HOSTNAME,
                f"hostname ends with reserved suffix {suffix!r}",
            )

    if not _STRICT_HOSTNAME_RE.match(hostname):
        return TargetRejection(
            hostname,
            TargetRejectionReason.INVALID_HOSTNAME,
            "hostname does not match RFC 1123 label rules",
        )

    if "." not in hostname:
        return TargetRejection(
            hostname,
            TargetRejectionReason.INVALID_HOSTNAME,
            "single-label hostnames are not scannable; use a fully qualified name or IP",
        )

    return None


def resolve_hostname(hostname: str, *, timeout: float = 5.0) -> list[str]:
    """Resolve a hostname to all of its A/AAAA records.

    Uses the system resolver but returns every address so the caller can
    validate all of them. Raises ``socket.gaierror`` on failure.
    """
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        # Strip any IPv6 zone id, e.g. "fe80::1%eth0".
        addr = addr.split("%", 1)[0]
        if addr not in addresses:
            addresses.append(addr)
    return addresses


# ---------------------------------------------------------------------------
# Public validation entry point
# ---------------------------------------------------------------------------


def validate_target(
    raw_target: str,
    *,
    allow_private: bool | None = None,
    allow_dns: bool = True,
) -> ValidatedTarget:
    """Validate a single scan target and return its vetted resolved addresses.

    Args:
        raw_target: Hostname or IP literal supplied by a user.
        allow_private: Override for the private-address policy. Defaults to the
            configured deployment policy.
        allow_dns: When False, only IP literals are accepted. Used by the HTTP
            client, which must not re-resolve a name mid-request.

    Returns:
        The validated target with every resolved address already vetted.

    Raises:
        UnsafeTargetError: when the target fails any check.
    """
    if raw_target is None:
        raise UnsafeTargetError(
            TargetRejection("", TargetRejectionReason.EMPTY, "target is missing")
        )

    if allow_private is None:
        allow_private = settings.allow_private_targets

    stripped = unicodedata.normalize("NFKC", str(raw_target)).strip()
    if not stripped:
        raise UnsafeTargetError(
            TargetRejection(str(raw_target), TargetRejectionReason.EMPTY, "target is empty")
        )

    # Split off a bracketed IPv6 literal, which contains colons.
    if stripped.startswith("["):
        close = stripped.find("]")
        if close == -1:
            raise UnsafeTargetError(
                TargetRejection(
                    stripped, TargetRejectionReason.MALFORMED, "unterminated IPv6 bracket"
                )
            )
        host_token = stripped[1:close]
        remainder = stripped[close + 1 :]
        if remainder and not remainder.startswith(":"):
            raise UnsafeTargetError(
                TargetRejection(
                    stripped, TargetRejectionReason.MALFORMED, "unexpected text after IPv6 literal"
                )
            )
    else:
        host_token = stripped.split(":", 1)[0] if stripped.count(":") == 1 else stripped

    literal = normalize_ip_literal(host_token)

    if literal is not None:
        reason = classify_address(literal, allow_private=allow_private)
        if reason is not None:
            raise UnsafeTargetError(
                TargetRejection(
                    stripped,
                    reason,
                    f"{literal} is refused by the network safety floor ({reason.value})",
                )
            )
        return ValidatedTarget(hostname=str(literal), addresses=(str(literal),), resolved_via="literal")

    # Not an IP literal -> must be a DNS name.
    hostname = normalize_hostname(host_token)
    syntax_error = validate_hostname_syntax(hostname)
    if syntax_error is not None:
        raise UnsafeTargetError(syntax_error)

    if not allow_dns:
        raise UnsafeTargetError(
            TargetRejection(
                stripped,
                TargetRejectionReason.MALFORMED,
                "DNS names are not accepted here; supply an IP literal",
            )
        )

    try:
        addresses = resolve_hostname(hostname, timeout=settings.scan_timeout_seconds)
    except socket.gaierror as exc:
        raise UnsafeTargetError(
            TargetRejection(stripped, TargetRejectionReason.DNS_FAILURE, f"resolution failed: {exc}")
        ) from exc

    if not addresses:
        raise UnsafeTargetError(
            TargetRejection(
                stripped, TargetRejectionReason.DNS_FAILURE, "hostname resolved to no addresses"
            )
        )

    # Every resolved address must pass. A name with one good and one bad address
    # is refused outright: allowing it would make the outcome depend on resolver
    # ordering, which is exactly the rebinding primitive we are defending against.
    for addr_text in addresses:
        try:
            addr = ipaddress.ip_address(addr_text)
        except ValueError as exc:
            raise UnsafeTargetError(
                TargetRejection(
                    stripped,
                    TargetRejectionReason.MALFORMED,
                    f"resolver returned unparseable address {addr_text!r}",
                )
            ) from exc
        reason = classify_address(addr, allow_private=allow_private)
        if reason is not None:
            raise UnsafeTargetError(
                TargetRejection(
                    stripped,
                    reason,
                    f"resolved address {addr} is refused by the network safety floor "
                    f"({reason.value})",
                )
            )

    return ValidatedTarget(hostname=hostname, addresses=tuple(addresses), resolved_via="dns")


def validate_targets(
    targets: list[str],
    *,
    allow_private: bool | None = None,
) -> ValidationResult:
    """Validate many targets, collecting rejections instead of raising."""
    result = ValidationResult()
    for target in targets:
        try:
            result.accepted.append(
                validate_target(target, allow_private=allow_private)
            )
        except UnsafeTargetError as exc:
            result.rejected.append(exc.rejection)
    return result


def validate_port(port: int, *, allowed: list[int] | None = None) -> TargetRejection | None:
    """Ensure a port is inside the deployment's allowed scan set."""
    if not isinstance(port, int) or isinstance(port, bool):
        return TargetRejection(str(port), TargetRejectionReason.PORT_NOT_ALLOWED, "port must be an int")
    if not 1 <= port <= 65535:
        return TargetRejection(
            str(port), TargetRejectionReason.PORT_NOT_ALLOWED, "port outside 1-65535"
        )
    permitted = allowed if allowed is not None else settings.allowed_ports
    if port not in permitted:
        return TargetRejection(
            str(port),
            TargetRejectionReason.PORT_NOT_ALLOWED,
            "port is not in VEYL_ALLOWED_SCAN_PORTS for this deployment",
        )
    return None
