"""Contracts every collector and scanner backend must satisfy.

Keeping these as Protocol classes (rather than an ABC) means a new backend — an
Nmap adapter, an external ASM feed, a lab fixture — only has to *look* right,
and the rest of the system never learns which one is in use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from veyl_api.enums import Confidence, Provenance


@dataclass
class ObservationPayload:
    """One fact collected about one subject.

    ``data`` is the verbatim payload. It is treated as hostile everywhere
    downstream: sanitised before storage, never interpolated into SQL, never
    rendered unescaped, never passed to a shell.
    """

    kind: str
    subject: str
    data: dict[str, Any]
    provenance: Provenance = Provenance.OBSERVED
    confidence: Confidence = Confidence.HIGH
    observed_at: datetime | None = None
    asset_key: str | None = None

    # Convenience: a short human summary used in evidence rendering.
    summary: str = ""


@dataclass
class PortResult:
    """Outcome of probing one TCP port."""

    port: int
    state: str  # "open" | "closed" | "filtered"
    latency_ms: float | None = None
    error: str | None = None


@dataclass
class CollectResult:
    """Everything one collector produced for one target."""

    observations: list[ObservationPayload] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    #: Populated by collectors that discover sub-assets (DNS, CT).
    discovered_names: list[str] = field(default_factory=list)


@dataclass
class ScanRequest:
    """A fully validated, in-scope target ready to be probed.

    By the time this object exists, both the network safety floor and the scope
    guard have already passed. Collectors can therefore assume the target is
    legitimate and should not re-implement policy checks.
    """

    hostname: str
    addresses: tuple[str, ...]
    ports: tuple[int, ...]
    organization_id: str
    scope_entry_id: str | None = None
    timeout_seconds: float = 5.0
    user_agent: str = "Veyl/0.1"
    #: When False, collectors must not follow redirects or crawl.
    follow_redirects: bool = False
    #: Set by the runner so a single slow target cannot stall a whole scan.
    deadline: datetime | None = None


@runtime_checkable
class PortScannerBackend(Protocol):
    """A port scanner. The built-in TCP connect scanner implements this."""

    name: str

    def scan_ports(self, request: ScanRequest, ports: list[int]) -> list[PortResult]:
        """Probe ``ports`` on ``request`` and return a result per port."""
        ...

    def is_available(self) -> bool:
        """Whether this backend can run in the current environment."""
        ...


@runtime_checkable
class Collector(Protocol):
    """A collector turns a validated target into observations."""

    name: str

    def collect(self, request: ScanRequest) -> CollectResult:
        """Collect observations. Must not raise; report failures in ``errors``."""
        ...


@dataclass
class CollectorRegistration:
    """Describes a collector so the runner and UI can reason about it."""

    name: str
    description: str
    produces: list[str]
    requires_ports: list[int] = field(default_factory=list)
    always_run: bool = False
