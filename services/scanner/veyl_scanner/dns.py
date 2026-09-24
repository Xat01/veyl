"""DNS collection: A/AAAA records, CNAMEs, MX/TXT, and subdomain discovery.

Subdomain discovery is deliberately in-scope-only. A name found via Certificate
Transparency or a DNS wordlist is reported as a *candidate*, and the runner
re-runs it through the scope guard before it is ever probed. Discovery never
grants authorization.
"""

from __future__ import annotations

import socket
from typing import Any

import dns.exception
import dns.resolver

from veyl_api.enums import Confidence, Provenance
from veyl_scanner.contracts import CollectResult, CollectorRegistration, ObservationPayload, ScanRequest

#: A short, high-signal wordlist. Veyl is not a brute-forcer: this exists to
#: surface the names that are almost always live on real estates, and every hit
#: is still subject to the scope guard before probing.
COMMON_SUBDOMAINS: tuple[str, ...] = (
    "www",
    "api",
    "app",
    "admin",
    "portal",
    "dashboard",
    "login",
    "auth",
    "sso",
    "mail",
    "smtp",
    "imap",
    "vpn",
    "remote",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "staging",
    "stage",
    "dev",
    "test",
    "qa",
    "demo",
    "sandbox",
    "internal",
    "intranet",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "cache",
    "metrics",
    "grafana",
    "kibana",
    "monitor",
    "status",
    "cdn",
    "static",
    "assets",
    "media",
    "files",
    "docs",
    "wiki",
    "support",
    "help",
)

_DEFAULT_RESOLVER_TIMEOUT = 4.0


def _resolver(timeout: float = _DEFAULT_RESOLVER_TIMEOUT) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 2.0)
    return resolver


def resolve_records(
    name: str, record_type: str, timeout: float = _DEFAULT_RESOLVER_TIMEOUT
) -> list[str]:
    """Return string records of ``record_type`` for ``name``. Empty on any failure.

    Never raises: a hostile or broken DNS server must not abort a scan.
    """
    try:
        answers = _resolver(timeout).resolve(name, record_type)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
        OSError,
    ):
        return []

    out: list[str] = []
    for answer in answers:
        try:
            if record_type in {"A", "AAAA"}:
                out.append(str(answer.address))
            elif record_type == "CNAME":
                out.append(str(answer.target).rstrip("."))
            elif record_type in {"NS", "PTR"}:
                out.append(str(answer.target).rstrip("."))
            elif record_type == "MX":
                out.append(str(answer.exchange).rstrip("."))
            elif record_type == "TXT":
                chunks = getattr(answer, "strings", None)
                if chunks:
                    out.append(b"".join(chunks).decode("utf-8", errors="replace"))
                else:
                    out.append(str(answer).strip('"'))
            else:
                out.append(str(answer).rstrip("."))
        except (AttributeError, ValueError):
            continue
    return out


def resolves_to_any(name: str, timeout: float = _DEFAULT_RESOLVER_TIMEOUT) -> list[str]:
    """Convenience wrapper returning A + AAAA addresses for a name."""
    return [
        *resolve_records(name, "A", timeout),
        *resolve_records(name, "AAAA", timeout),
    ]


class DnsCollector:
    """Collects DNS facts and proposes candidate subdomains."""

    name = "dns"
    registration = CollectorRegistration(
        name="dns",
        description="Resolves A/AAAA/CNAME/MX/TXT/NS and proposes candidate subdomains.",
        produces=["dns_records", "dns_cname", "dns_mx", "dns_txt", "dns_ns"],
        always_run=True,
    )

    def __init__(self, *, discover_subdomains: bool = True) -> None:
        self.discover_subdomains = discover_subdomains

    def collect(self, request: ScanRequest) -> CollectResult:
        result = CollectResult()
        host = request.hostname
        timeout = max(0.5, min(request.timeout_seconds, _DEFAULT_RESOLVER_TIMEOUT))

        for record_type, kind in (
            ("A", "dns_a"),
            ("AAAA", "dns_aaaa"),
            ("CNAME", "dns_cname"),
            ("MX", "dns_mx"),
            ("NS", "dns_ns"),
        ):
            records = resolve_records(host, record_type, timeout)
            if records:
                result.observations.append(
                    ObservationPayload(
                        kind=kind,
                        subject=host,
                        asset_key=host,
                        data={"hostname": host, "record_type": record_type, "records": records},
                        provenance=Provenance.OBSERVED,
                        confidence=Confidence.HIGH,
                        summary=f"{record_type} records for {host}: {', '.join(records[:6])}",
                    )
                )

        txt_records = resolve_records(host, "TXT", timeout)
        if txt_records:
            result.observations.append(
                ObservationPayload(
                    kind="dns_txt",
                    subject=host,
                    asset_key=host,
                    data={"hostname": host, "record_type": "TXT", "records": txt_records},
                    provenance=Provenance.OBSERVED,
                    confidence=Confidence.HIGH,
                    # SPF/DMARC/verification records frequently leak infrastructure
                    # names, which matters later for correlation.
                    summary=f"TXT records for {host} ({len(txt_records)} entries)",
                )
            )

        if self.discover_subdomains:
            result.discovered_names = self._propose_subdomains(host, timeout=min(timeout, 1.5))

        return result

    def _propose_subdomains(self, host: str, *, timeout: float) -> list[str]:
        """Resolve a bounded wordlist and return the names that exist.

        Returns candidates only. The runner re-checks each against the scope
        guard; a discovered name that is not authorized is reported as a
        candidate and never probed.
        """
        found: list[str] = []
        for label in COMMON_SUBDOMAINS:
            candidate = f"{label}.{host}"
            if resolves_to_any(candidate, timeout=timeout):
                found.append(candidate)
        return found


def socket_resolve(hostname: str) -> list[str]:
    """System-resolver fallback used when dnspython is unavailable."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    seen: list[str] = []
    for info in infos:
        addr = info[4][0].split("%", 1)[0]
        if addr not in seen:
            seen.append(addr)
    return seen


def spf_and_dmarc_records(host: str, timeout: float = _DEFAULT_RESOLVER_TIMEOUT) -> dict[str, Any]:
    """Extract SPF and DMARC posture from TXT records.

    Reported as observations, not findings: a missing SPF record is a real
    weakness but it belongs to mail configuration, and the rule engine decides
    whether to raise it.
    """
    txt = resolve_records(host, "TXT", timeout)
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    dmarc = resolve_records(f"_dmarc.{host}", "TXT", timeout)
    return {"spf": spf, "dmarc": dmarc, "all_txt": txt}
