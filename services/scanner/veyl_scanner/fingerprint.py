"""Service fingerprinting.

A fingerprint is a claim about what is listening on a port. Veyl's rule is that
a claim must be *earned*: name the product only when the banner says so, name
the version only when the banner contains one, and otherwise report
``unknown``.

``unknown`` is a first-class, correct answer and it is far better than a
plausible-looking wrong one, because a wrong product name would later cause a
wrong CVE correlation, and a wrong CVE is worse than no CVE at all.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Any

from veyl_api.enums import Confidence


@dataclass
class ServiceFingerprint:
    """What we concluded is listening on one port, and why."""

    port: int
    service_name: str = "unknown"
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    confidence: Confidence = Confidence.LOW
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
        }


#: Port to the service name that is conventionally expected there. This is a
#: *hypothesis* only, and it is recorded as weak evidence at LOW confidence
#: unless a banner confirms it.
WELL_KNOWN_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "smtp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3000: "http",
    3306: "mysql",
    3389: "rdp",
    4443: "https",
    5000: "http",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    7001: "weblogic",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8083: "http",
    8086: "influxdb",
    8088: "http",
    8090: "http",
    8161: "activemq",
    8443: "https",
    8834: "nessus",
    8888: "http",
    9000: "http",
    9042: "cassandra",
    9090: "http",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch",
    9443: "https",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq-management",
    27017: "mongodb",
    27018: "mongodb",
    50000: "sap",
}

#: Probes used to elicit a banner. Each entry is (payload bytes, read_expected).
#: All payloads are read-only greetings or protocol verbs; nothing here mutates
#: state. Notably absent: any write, delete, or config-changing verb.
BANNER_PROBES: dict[int, list[tuple[bytes, bool]]] = {
    22: [(b"", True)],  # SSH sends its identification string unprompted
    21: [(b"", True)],  # FTP sends its greeting
    25: [(b"", True)],
    110: [(b"", True)],
    143: [(b"", True)],
    3306: [(b"", True)],  # MySQL sends a handshake packet
    6379: [(b"PING\r\n", True)],  # minimal, non-mutating command
    27017: [(b"", False)],
}

#: Banner patterns. Ordered most specific first. A pattern only sets a version
#: when the capture group actually contains one.
_BANNER_RULES: tuple[tuple[re.Pattern[str], str, str | None, Confidence], ...] = (
    (re.compile(r"^SSH-\d+\.\d+-(?P<product>[A-Za-z0-9_.\-]+?)[_ ](?P<version>[\w.\-p]+)", re.I),
     "ssh", "product", Confidence.HIGH),
    (re.compile(r"^SSH-2\.0-(?P<product>[A-Za-z0-9_.\-]+)", re.I), "ssh", "product", Confidence.MEDIUM),
    (re.compile(r"^220[- ].*(?P<product>ProFTPD|vsFTPd|Pure-FTPd|FileZilla|Microsoft FTP)[ /](?P<version>[\d.p]+)?", re.I),
     "ftp", "product", Confidence.HIGH),
    (re.compile(r"^220[- ].*Microsoft ESMTP", re.I), "smtp", None, Confidence.HIGH),
    (re.compile(r"^220[- ].*(?P<product>Postfix|Exim|Sendmail)(?: ESMTP)?(?: (?P<version>[\d.]+))?", re.I),
     "smtp", "product", Confidence.HIGH),
    (re.compile(r"^\+OK.*(?P<product>Dovecot)", re.I), "pop3", "product", Confidence.MEDIUM),
    (re.compile(r"^\*\ OK.*(?P<product>Dovecot)", re.I), "imap", "product", Confidence.MEDIUM),
    (re.compile(r"(?P<product>MySQL|MariaDB)", re.I), "mysql", "product", Confidence.MEDIUM),
    (re.compile(r"^-ERR.*(?P<product>redis)", re.I), "redis", "product", Confidence.HIGH),
)

#: MySQL/MariaDB handshake version extraction (the banner is mostly binary).
_MYSQL_VERSION_RE = re.compile(rb"(\d+\.\d+\.\d+)[\x00\-]")


def _read_banner(sock: socket.socket, *, read: bool, timeout: float, max_bytes: int = 4096) -> str:
    """Read up to ``max_bytes`` from a socket, never raising."""
    if not read:
        return ""
    try:
        sock.settimeout(timeout)
        data = sock.recv(max_bytes)
        return data.decode("utf-8", errors="replace")
    except (TimeoutError, socket.timeout, OSError):
        return ""


def _classify_banner(banner: str) -> tuple[str, str | None, str | None, Confidence] | None:
    """Map a banner to (service, product, version, confidence).

    Returns ``None`` when nothing matches, which leaves the port as ``unknown``.
    """
    if not banner.strip():
        return None
    text = banner.strip()
    for pattern, service, _, confidence in _BANNER_RULES:
        match = pattern.search(text)
        if not match:
            continue
        groups = match.groupdict()
        product = groups.get("product")
        version = groups.get("version")
        if product:
            product = product.strip()
        if version:
            version = version.strip().strip(".-_")
            # Guard against capturing something that is not version-like.
            if not any(ch.isdigit() for ch in version):
                version = None
        return service, product or None, version, confidence
    return None


def fingerprint_port(
    hostname: str,
    address: str,
    port: int,
    timeout: float,
) -> ServiceFingerprint:
    """Probe one port and return a fingerprint with its evidence chain."""
    result = ServiceFingerprint(port=port)

    expected_service = WELL_KNOWN_PORTS.get(port)
    banner = ""
    probes = BANNER_PROBES.get(port, [(b"", True)])

    for payload, expect_read in probes:
        sock = None
        try:
            sock = socket.create_connection((address, port), timeout=timeout)
            if payload:
                sock.sendall(payload)
            banner = _read_banner(sock, read=expect_read, timeout=min(timeout, 3.0))
        except (TimeoutError, socket.timeout, OSError):
            banner = ""
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if banner:
            break

    # Special-case the binary MySQL handshake for a version.
    if port == 3306 and banner:
        mysql_match = _MYSQL_VERSION_RE.search(banner.encode("utf-8", errors="replace"))
        if mysql_match:
            result.service_name = "mysql"
            result.product = "MySQL"
            result.version = mysql_match.group(1).decode("ascii", errors="replace")
            result.banner = banner[:512]
            result.confidence = Confidence.MEDIUM
            result.evidence.append(
                {
                    "method": "mysql_handshake",
                    "detail": "version string extracted from the MySQL initial handshake packet",
                    "observed": result.version,
                }
            )
            return result

    classified = _classify_banner(banner)

    if classified is not None:
        service, product, version, confidence = classified
        result.service_name = service
        result.product = product
        result.version = version
        result.banner = banner[:512]
        result.confidence = confidence
        result.evidence.append(
            {
                "method": "banner_match",
                "detail": f"banner matched the {service} signature",
                "observed": banner[:200],
            }
        )
        return result

    # No banner: fall back to what the port conventionally means, but say so.
    if expected_service:
        result.service_name = expected_service
        result.product = None
        result.version = None
        result.confidence = Confidence.LOW
        result.evidence.append(
            {
                "method": "port_convention",
                "detail": (
                    f"TCP/{port} is conventionally {expected_service}, but no banner was "
                    f"retrieved to confirm it; product and version are deliberately unset"
                ),
                "observed": f"tcp/{port} open",
            }
        )
        if banner:
            result.banner = banner[:512]
        return result

    result.service_name = "unknown"
    result.confidence = Confidence.LOW
    result.evidence.append(
        {
            "method": "no_match",
            "detail": "no banner and no well-known convention for this port",
            "observed": f"tcp/{port} open",
        }
    )
    if banner:
        result.banner = banner[:512]
    return result


def fingerprint_services(
    hostname: str,
    address: str,
    open_ports: list[int],
    timeout: float,
) -> list[ServiceFingerprint]:
    """Fingerprint every open port, isolating failures per port."""
    results: list[ServiceFingerprint] = []
    for port in open_ports:
        try:
            results.append(fingerprint_port(hostname, address, port, timeout))
        except Exception:  # noqa: BLE001 - one bad port must not fail the target
            results.append(
                ServiceFingerprint(
                    port=port,
                    service_name="unknown",
                    confidence=Confidence.LOW,
                    evidence=[
                        {
                            "method": "error",
                            "detail": "fingerprinting raised; port reported as unknown",
                            "observed": f"tcp/{port} open",
                        }
                    ],
                )
            )
    return results
