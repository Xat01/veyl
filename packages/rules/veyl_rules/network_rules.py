"""Network and infrastructure detection rules.

These rules reason about which ports are reachable, and whether a service that
should never face the internet is exposed to it.

Severity here is calibrated on *exposure plus class of service*, never on the
port number alone. An open 5432 on an internal-only host is not the same finding
as an open 5432 on an internet-reachable host, and the rules say so.
"""

from __future__ import annotations

from veyl_api.enums import Confidence, RuleCategory, Severity
from veyl_rules.framework import RuleContext, RuleDefinition, RuleMatch

#: Services whose exposure to the internet is almost never intentional.
DATABASE_PORTS: dict[int, str] = {
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    9042: "Cassandra",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
}

ADMIN_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB",
    2375: "Docker daemon (unencrypted)",
    2376: "Docker daemon",
    3389: "Remote Desktop",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6443: "Kubernetes API",
    8080: "Alternate HTTP (often an admin console)",
    8443: "Alternate HTTPS (often an admin console)",
    9200: "Elasticsearch",
    10000: "Webmin",
    15672: "RabbitMQ management",
}

#: Ports that are on this list are reported as informational rather than as a
#: default-deny finding, because they are commonly and legitimately public.
_NORMAL_PUBLIC_PORTS = frozenset({80, 443, 25, 465, 587, 53})


def _open_ports(context: RuleContext) -> list[int]:
    scan = context.first("port_scan")
    if not scan:
        return []
    ports = scan.get("open_ports", [])
    return sorted(int(p) for p in ports if isinstance(p, int | str) and str(p).isdigit())


def _service_for(context: RuleContext, port: int) -> dict | None:
    for obs in context.of_kind("service_fingerprint"):
        if obs.get("port") == port:
            return obs
    return None


def check_exposed_database(context: RuleContext) -> list[RuleMatch]:
    """Database or cache ports reachable from the assessed network position."""
    matches: list[RuleMatch] = []
    for port in _open_ports(context):
        product = DATABASE_PORTS.get(port)
        if product is None:
            continue

        service = _service_for(context, port)
        observed_name = (service or {}).get("service_name", "unknown")
        port_scan = context.first("port_scan") or {}

        # Confidence depends on whether we confirmed the product or only
        # inferred it from the port convention.
        confirmed = bool(service and service.get("product"))
        confidence = Confidence.HIGH if confirmed else Confidence.MEDIUM

        evidence = [
            {
                "kind": "port_scan",
                "matcher": f"open_ports contains {port}",
                "detail": {
                    "port": port,
                    "state": "open",
                    "scanner": port_scan.get("scanner"),
                    "hostname": port_scan.get("hostname"),
                },
            }
        ]
        if service:
            evidence.append(
                {
                    "kind": "service_fingerprint",
                    "matcher": f"service_fingerprint.port == {port}",
                    "detail": {
                        "port": port,
                        "service_name": observed_name,
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "confidence": service.get("confidence"),
                        "fingerprint_evidence": service.get("evidence"),
                    },
                }
            )

        product_phrase = (
            f"confirmed as {service.get('product')}"
            if confirmed and service and service.get("product")
            else f"whose port is conventionally {product}"
        )
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{port}",
                summary=f"{product} is reachable on TCP/{port}",
                detection_explanation=(
                    f"TCP/{port} responded as open during the port sweep and the service on it "
                    f"was {product_phrase}. Veyl determined this from the port state recorded by "
                    f"the scanner"
                    + (
                        " and the service banner it retrieved."
                        if confirmed
                        else "; it did not retrieve a banner, so the product is inferred from the "
                        "port convention and the confidence is MEDIUM rather than HIGH."
                    )
                ),
                impact=(
                    f"{product} is a data store. Data stores are designed to be reached by the "
                    f"application tier, not by arbitrary hosts. Where one is reachable more "
                    f"broadly than intended, the primary risks are: authentication weaknesses "
                    f"becoming directly reachable, unauthenticated administrative commands in "
                    f"services that assume a trusted network (Redis and Memcached in particular), "
                    f"and bulk data extraction if credentials are weak or reused. Veyl has "
                    f"observed reachability only; it has not attempted to authenticate or read "
                    f"data."
                ),
                evidence=evidence,
                confidence=confidence,
                risk_factors={
                    "service_class": "database",
                    "port": port,
                    "confirmed_product": confirmed,
                },
            )
        )
    return matches


def check_exposed_administrative_service(context: RuleContext) -> list[RuleMatch]:
    """Remote-administration services reachable from the assessed position."""
    matches: list[RuleMatch] = []
    for port in _open_ports(context):
        label = ADMIN_PORTS.get(port)
        if label is None:
            continue

        service = _service_for(context, port)
        lower_port = port in {2375, 2376, 5985, 5986, 6443, 10000, 15672}
        severity = Severity.HIGH if lower_port else Severity.MEDIUM
        # Telnet is plaintext and always a genuine problem when exposed.
        if port == 23:
            severity = Severity.HIGH

        port_scan = context.first("port_scan") or {}
        evidence = [
            {
                "kind": "port_scan",
                "matcher": f"open_ports contains {port}",
                "detail": {
                    "port": port,
                    "state": "open",
                    "scanner": port_scan.get("scanner"),
                    "hostname": port_scan.get("hostname"),
                },
            }
        ]
        if service:
            evidence.append(
                {
                    "kind": "service_fingerprint",
                    "matcher": f"service_fingerprint.port == {port}",
                    "detail": {
                        "port": port,
                        "service_name": service.get("service_name"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "banner": service.get("banner"),
                    },
                }
            )

        matches.append(
            RuleMatch(
                subject_suffix=f"port-{port}",
                summary=f"{label} administrative service reachable on TCP/{port}",
                detection_explanation=(
                    f"TCP/{port} reported open. This port carries {label}, an administrative or "
                    f"remote-access interface. "
                    + (
                        f"The service banner identified it as "
                        f"{service.get('product') or service.get('service_name')}."
                        if service and service.get("product")
                        else "No banner was retrieved, so the identification comes from the port "
                        "convention."
                    )
                ),
                impact=(
                    f"Administrative interfaces are high-value targets because they grant control "
                    f"rather than data alone. Reachability does not by itself mean the interface is "
                    f"weakly protected: Veyl has not attempted authentication. What it does mean is "
                    f"that every credential-stuffing campaign, exposed-key scan and vulnerability "
                    f"in {label} now has a directly reachable target, and that any authentication "
                    f"bypass in that software is exploitable from the assessed position. "
                    + (
                        "Telnet transmits credentials in cleartext, so any network observer can "
                        "recover them."
                        if port == 23
                        else ""
                    )
                ),
                evidence=evidence,
                severity=severity,
                confidence=Confidence.HIGH if service else Confidence.MEDIUM,
                risk_factors={
                    "service_class": "administrative",
                    "port": port,
                    "control_plane": lower_port or port in {22, 3389, 445},
                },
            )
        )
    return matches


def check_unexpected_high_port(context: RuleContext) -> list[RuleMatch]:
    """Open high ports that are neither a standard service nor obviously expected.

    Reported at INFO. Veyl's position is that an unfamiliar listener is worth a
    human looking at, and is not by itself a vulnerability. This rule exists to
    surface it without crying wolf.
    """
    matches: list[RuleMatch] = []
    for port in _open_ports(context):
        if port < 1024 or port in _NORMAL_PUBLIC_PORTS:
            continue
        if port in DATABASE_PORTS or port in ADMIN_PORTS:
            continue

        service = _service_for(context, port)
        port_scan = context.first("port_scan") or {}
        name = (service or {}).get("service_name", "unknown")

        matches.append(
            RuleMatch(
                subject_suffix=f"port-{port}",
                summary=f"Unclassified listener on TCP/{port} ({name})",
                detection_explanation=(
                    f"TCP/{port} accepted a connection. The fingerprint for this port is "
                    f"{name!r} with confidence "
                    f"{(service or {}).get('confidence', 'LOW')}. This port is not a conventional "
                    f"public service port, so Veyl is reporting it for review rather than "
                    f"asserting a problem."
                ),
                impact=(
                    "The significance depends entirely on what this service is. A deliberately "
                    "published application port is expected; a listener that nobody on the team "
                    "recognises is how temporary staging systems become permanently exposed. Veyl "
                    "cannot determine intent from a port state."
                ),
                evidence=[
                    {
                        "kind": "port_scan",
                        "matcher": f"open_ports contains {port}",
                        "detail": {
                            "port": port,
                            "state": "open",
                            "scanner": port_scan.get("scanner"),
                        },
                    },
                    {
                        "kind": "service_fingerprint",
                        "matcher": f"service_fingerprint.port == {port}",
                        "detail": {
                            "port": port,
                            "service_name": name,
                            "product": (service or {}).get("product"),
                            "version": (service or {}).get("version"),
                            "confidence": (service or {}).get("confidence"),
                        },
                    },
                ],
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                risk_factors={"service_class": "unclassified", "port": port},
            )
        )
    return matches


def check_cleartext_service(context: RuleContext) -> list[RuleMatch]:
    """Protocols that carry credentials in cleartext by design."""
    matches: list[RuleMatch] = []
    cleartext = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 80: "HTTP"}

    for port in _open_ports(context):
        label = cleartext.get(port)
        if label is None:
            continue
        # HTTP on 80 is only notable if there is no HTTPS counterpart, because a
        # redirect to HTTPS is the correct configuration and must not be flagged.
        if port == 80 and (443 in _open_ports(context) or 8443 in _open_ports(context)):
            continue

        service = _service_for(context, port)
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{port}",
                summary=f"{label} service offered without transport encryption on TCP/{port}",
                detection_explanation=(
                    f"TCP/{port} is open and carries {label}, which transmits its payload in "
                    f"cleartext. "
                    + (
                        "No HTTPS listener was observed on this host, so the service is not "
                        "merely being kept alive to perform a redirect."
                        if port == 80
                        else "This protocol has no encrypted mode on this port."
                    )
                ),
                impact=(
                    f"Any party able to observe the network path can read {label} traffic, and "
                    f"for FTP, Telnet, POP3 and IMAP that includes the credentials. This matters "
                    f"most on shared or untrusted networks but is a genuine exposure wherever the "
                    f"path is not fully trusted."
                ),
                evidence=[
                    {
                        "kind": "port_scan",
                        "matcher": f"open_ports contains {port}",
                        "detail": {"port": port, "state": "open", "open_ports": _open_ports(context)},
                    },
                    {
                        "kind": "service_fingerprint",
                        "matcher": f"service_fingerprint.port == {port}",
                        "detail": {
                            "port": port,
                            "service_name": (service or {}).get("service_name"),
                            "banner": (service or {}).get("banner"),
                        },
                    },
                ],
                severity=Severity.MEDIUM if port != 80 else Severity.LOW,
                confidence=Confidence.HIGH,
                risk_factors={"service_class": "cleartext", "port": port},
            )
        )
    return matches


def check_port_surface_growth(context: RuleContext) -> list[RuleMatch]:
    """A host exposing an unusually large number of ports.

    Informational. A wide surface is not a vulnerability, but it is a
    maintenance signal worth surfacing once.
    """
    ports = _open_ports(context)
    if len(ports) < 15:
        return []

    return [
        RuleMatch(
            subject_suffix="wide-surface",
            summary=f"{len(ports)} open TCP ports observed",
            detection_explanation=(
                f"The port sweep found {len(ports)} listening ports: "
                f"{', '.join(str(p) for p in ports[:40])}"
                f"{'...' if len(ports) > 40 else ''}. Veyl reports the count and the list; it does "
                f"not assume the services are unwanted."
            ),
            impact=(
                "Each listening port is maintenance surface. A host with a wide unknown surface is "
                "harder to keep patched and harder to reason about during an incident, but a wide "
                "surface may be entirely correct for the role of the host."
            ),
            evidence=[
                {
                    "kind": "port_scan",
                    "matcher": f"len(open_ports) >= 15 (got {len(ports)})",
                    "detail": {"open_ports": ports, "count": len(ports)},
                }
            ],
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            risk_factors={"service_class": "surface", "open_port_count": len(ports)},
        )
    ]


NETWORK_RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="VEYL-NET-001",
        title="Internet-exposed database service",
        category=RuleCategory.NETWORK,
        severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        description=(
            "A database or cache service is reachable on the network. Data stores are not "
            "intended to be directly reachable by arbitrary hosts."
        ),
        detection=(
            "Fires when the port sweep reports an open port that belongs to a known database "
            "class (MySQL 3306, PostgreSQL 5432, MSSQL 1433, MongoDB 27017/27018, Redis 6379, "
            "Memcached 11211, Elasticsearch 9200, Cassandra 9042, Oracle 1521, CouchDB 5984). "
            "Confidence is HIGH when a service banner confirmed the product and MEDIUM when the "
            "conclusion rests on the port convention alone."
        ),
        evidence_requirements=["port_scan", "service_fingerprint (optional)"],
        remediation=(
            "Confirm whether the host is intended to serve that database to the public internet. "
            "If not, restrict access at the network layer (security group, firewall, private "
            "subnet) to the application tier that needs it. Verify that the database requires "
            "strong authentication independent of network position, since network controls are "
            "frequently the only control in place."
        ),
        check=check_exposed_database,
        requires=["port_scan"],
    ),
    RuleDefinition(
        rule_id="VEYL-NET-002",
        title="Internet-exposed administrative service",
        category=RuleCategory.NETWORK,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description=(
            "A remote-administration interface (SSH, RDP, SMB, VNC, Docker or Kubernetes "
            "control plane, management console) is reachable on the network."
        ),
        detection=(
            "Fires when the port sweep reports an open port belonging to an administrative class. "
            "Severity is raised to HIGH for control-plane services where a single successful "
            "authentication grants broad control: Docker API (2375/2376), Kubernetes API (6443), "
            "WinRM (5985/5986), Webmin (10000), RabbitMQ management (15672), and Telnet (23) "
            "because it is cleartext."
        ),
        evidence_requirements=["port_scan", "service_fingerprint (optional)"],
        remediation=(
            "Place administrative interfaces behind a bastion host, VPN, or zero-trust access "
            "proxy so they are not directly reachable. Where direct access is required, enforce "
            "key-based or MFA authentication and rate-limit authentication attempts. Replace "
            "Telnet with SSH."
        ),
        check=check_exposed_administrative_service,
        requires=["port_scan"],
    ),
    RuleDefinition(
        rule_id="VEYL-NET-003",
        title="Cleartext protocol exposed",
        category=RuleCategory.NETWORK,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description=(
            "A protocol that transmits its payload, including credentials, without transport "
            "encryption is reachable."
        ),
        detection=(
            "Fires for open FTP (21), Telnet (23), POP3 (110) and IMAP (143). For HTTP (80) it "
            "fires only when no HTTPS listener (443 or 8443) was observed on the same host, so a "
            "correct HTTP-to-HTTPS redirect is not reported."
        ),
        evidence_requirements=["port_scan"],
        remediation=(
            "Migrate to the encrypted equivalent: FTPS or SFTP for FTP, SSH for Telnet, POP3S "
            "for POP3, IMAPS for IMAP, HTTPS for HTTP. Where cleartext must remain for a legacy "
            "client, restrict reachability to a trusted network segment."
        ),
        check=check_cleartext_service,
        requires=["port_scan"],
    ),
    RuleDefinition(
        rule_id="VEYL-NET-004",
        title="Unclassified network listener",
        category=RuleCategory.NETWORK,
        severity=Severity.INFO,
        default_confidence=Confidence.HIGH,
        description=(
            "A non-standard high port is listening. Reported for review rather than as a "
            "vulnerability."
        ),
        detection=(
            "Fires for any open port above 1024 that is not a known database port, not a known "
            "administrative port, and not a conventional public service port."
        ),
        evidence_requirements=["port_scan", "service_fingerprint"],
        remediation=(
            "Identify what is listening on the port and confirm the exposure is intended. If it "
            "is not, restrict access or decommission the listener."
        ),
        check=check_unexpected_high_port,
        requires=["port_scan"],
    ),
    RuleDefinition(
        rule_id="VEYL-NET-005",
        title="Wide open-port surface",
        category=RuleCategory.NETWORK,
        severity=Severity.INFO,
        default_confidence=Confidence.HIGH,
        description="A single host exposes fifteen or more listening TCP ports.",
        detection="Fires when the port sweep reports fifteen or more open ports on one asset.",
        evidence_requirements=["port_scan"],
        remediation=(
            "Review the full port list against the intended role of the host and close anything "
            "that is not required."
        ),
        check=check_port_surface_growth,
        requires=["port_scan"],
    ),
]
