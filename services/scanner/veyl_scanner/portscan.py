"""TCP port scanning backends.

The default backend is a bounded TCP connect scan implemented on an asyncio
thread pool. It needs no privileges, no raw sockets, and no external binary,
which matters because the whole product must run for someone who has only
cloned the repository.

An Nmap-backed implementation is provided behind the same Protocol for
deployments that want it. Neither backend is privileged in the code: the runner
picks whichever ``is_available()`` reports, preferring Nmap when explicitly
enabled.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from veyl_api.config import settings
from veyl_scanner.contracts import CollectorRegistration, PortResult, ScanRequest

#: Ports that answer a TCP connect but are conventionally "closed" if filtered
#: mid-handshake; we report what we actually observed and let rules interpret.
_STATE_OPEN = "open"
_STATE_CLOSED = "closed"
_STATE_FILTERED = "filtered"


class TcpConnectScanner:
    """Non-privileged TCP connect scanner.

    Uses ``connect_ex`` on a vetted IP address. We always dial the address the
    safety floor validated, never the hostname, so a DNS answer that changes
    between validation and connection cannot redirect us.
    """

    name = "tcp_connect"
    registration = CollectorRegistration(
        name="tcp_connect",
        description=(
            "Non-privileged TCP connect scan against validated addresses. Requires no "
            "raw sockets and no external binary."
        ),
        produces=["port_state"],
    )

    def is_available(self) -> bool:
        return True

    def _probe(self, address: str, port: int, timeout: float) -> PortResult:
        started = time.perf_counter()
        sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((address, port))
            latency = (time.perf_counter() - started) * 1000.0
            if code == 0:
                return PortResult(port=port, state=_STATE_OPEN, latency_ms=round(latency, 2))
            # ECONNREFUSED (111 Linux / 10061 Windows) means the host is up and
            # actively refusing: definitively closed, not filtered.
            if code in (111, 10061):
                return PortResult(port=port, state=_STATE_CLOSED, latency_ms=round(latency, 2))
            return PortResult(
                port=port, state=_STATE_FILTERED, latency_ms=round(latency, 2), error=f"errno={code}"
            )
        except TimeoutError:
            return PortResult(port=port, state=_STATE_FILTERED, error="timeout")
        except OSError as exc:
            return PortResult(port=port, state=_STATE_FILTERED, error=str(exc))
        finally:
            sock.close()

    def scan_ports(self, request: ScanRequest, ports: list[int]) -> list[PortResult]:
        """Probe every (address, port) pair, bounded by the configured concurrency."""
        timeout = min(request.timeout_seconds, settings.scan_timeout_seconds)
        timeout = max(timeout, 0.1)
        max_workers = max(1, min(settings.scan_max_concurrency, 512))

        # One result per port. If any address answers, the port is reachable;
        # we prefer the "open" verdict over "closed" so a dual-stack host whose
        # AAAA record refuses does not mask an open A record.
        by_port: dict[int, PortResult] = {}
        tasks: list[tuple[str, int]] = [(addr, port) for port in ports for addr in request.addresses]

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self._probe, addr, port, timeout): (addr, port) for addr, port in tasks
            }
            for future in as_completed(futures):
                result = future.result()
                existing = by_port.get(result.port)
                if existing is None or existing.state != _STATE_OPEN and result.state == _STATE_OPEN:
                    by_port[result.port] = result

        return [by_port[port] for port in sorted(by_port)]


class NmapScanner:
    """Optional Nmap-backed scanner.

    Kept behind the same Protocol as the connect scanner. No shell is used:
    ``python-nmap`` builds an argument vector and calls the binary directly, and
    every scalar that reaches the command line — host, port, timing — is
    validated by the caller before this point (targets pass the safety floor;
    ports are integers from the allow-list).
    """

    name = "nmap"

    def __init__(self, binary: str | None = None) -> None:
        self.binary = binary or settings.nmap_binary
        self._available: bool | None = None

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            import nmap  # noqa: F401
        except ImportError:
            self._available = False
            return False
        import shutil

        self._available = shutil.which(self.binary) is not None
        return self._available

    def scan_ports(self, request: ScanRequest, ports: list[int]) -> list[PortResult]:
        if not self.is_available():
            raise RuntimeError("nmap backend requested but nmap or python-nmap is unavailable")

        import nmap  # imported lazily so the dependency stays optional

        scanner = nmap.PortScanner()
        port_spec = ",".join(str(p) for p in sorted(set(ports)))
        results: list[PortResult] = []

        for address in request.addresses:
            # Arguments are passed as a list to the binary; no shell interpolation.
            scanner.scan(
                hosts=address,
                ports=port_spec,
                arguments=f"-Pn -T4 --host-timeout {int(request.timeout_seconds)}s",
            )
            for host in scanner.all_hosts():
                for proto in ("tcp",):
                    if proto not in scanner[host]:
                        continue
                    for port, entry in scanner[host][proto].items():
                        state = str(entry.get("state", "unknown"))
                        mapped = (
                            _STATE_OPEN
                            if state == "open"
                            else _STATE_CLOSED
                            if state in {"closed", "open|filtered"}
                            else _STATE_FILTERED
                        )
                        results.append(PortResult(port=int(port), state=mapped))
        return sorted(results, key=lambda r: r.port)


def get_port_scanner() -> TcpConnectScanner | NmapScanner:
    """Select a backend according to configuration and availability.

    Preference order: Nmap when explicitly enabled *and* present, otherwise the
    built-in connect scanner. A misconfigured Nmap never breaks a scan; it
    degrades to the default and the scan records which backend ran.
    """
    if settings.nmap_enabled:
        nmap_backend = NmapScanner()
        if nmap_backend.is_available():
            return nmap_backend
    return TcpConnectScanner()
