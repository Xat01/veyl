"""Scan orchestration.

The runner is the only place that knows how collectors fit together. Its
contract is strict:

1. Every candidate target passes the network safety floor *and* the scope guard
   before any socket is opened. Refusals are recorded, never silently dropped.
2. Collectors never see an unauthorized target.
3. Results are observations only; findings come later, from rules.
4. A failure in one target or one collector never aborts the scan.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from veyl_api.config import settings
from veyl_api.db.base import utcnow
from veyl_api.enums import (
    AssetType,
    AuthorizationStatus,
    BusinessCriticality,
    ChangeSignificance,
    Confidence,
    DataClassification,
    Environment,
    FindingStatus,
    Provenance,
    ScanStatus,
    ScanTrigger,
)
from veyl_api.models import (
    Asset,
    AssetContext,
    AssetSnapshot,
    Certificate,
    ExposureChange,
    Finding,
    Observation,
    Scan,
    ScopeEntry,
    Service,
)
from veyl_api.safety.firewall import TargetRejection, TargetRejectionReason, UnsafeTargetError, validate_port, validate_target
from veyl_api.safety.scope import ScopeGuard
from veyl_api.security.sanitize import checksum, deep_sanitize_json, truncate
from veyl_scanner.contracts import CollectResult, ObservationPayload, ScanRequest
from veyl_scanner.dns import DnsCollector
from veyl_scanner.http import HttpCollector
from veyl_scanner.portscan import get_port_scanner
from veyl_scanner.tls import TlsCollector


@dataclass
class TargetPlan:
    """One asset the scan intends to assess."""

    hostname: str
    addresses: tuple[str, ...]
    scope_entry: ScopeEntry
    discovered_via: str = "scope_entry"
    discovered_from: str | None = None


@dataclass
class ScanOutcome:
    """Summary returned to the caller."""

    scan_id: str
    status: ScanStatus
    targets_scanned: int = 0
    targets_blocked: int = 0
    assets_found: int = 0
    services_found: int = 0
    observations_recorded: int = 0
    blocked: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


#: Asset type inference from a service name. Used to set asset_type, which the
#: UI and graph read; it is always marked INFERRED, never OBSERVED.
_SERVICE_ASSET_TYPE: dict[str, AssetType] = {
    "mysql": AssetType.DATABASE,
    "postgresql": AssetType.DATABASE,
    "mongodb": AssetType.DATABASE,
    "redis": AssetType.DATABASE,
    "mssql": AssetType.DATABASE,
    "oracle": AssetType.DATABASE,
    "elasticsearch": AssetType.DATABASE,
    "http": AssetType.APPLICATION,
    "https": AssetType.APPLICATION,
    "ssh": AssetType.SERVER,
    "ftp": AssetType.SERVER,
    "smtp": AssetType.SERVER,
    "rdp": AssetType.SERVER,
    "smb": AssetType.SERVER,
    "ldap": AssetType.SERVER,
}

_ADMIN_PORTS = frozenset({22, 23, 3389, 5900, 5901})
_DATABASE_PORTS = frozenset({1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 27017, 27018})
_ENCRYPTED_PORTS = frozenset({443, 465, 636, 993, 995, 8443, 9443})


def infer_environment(scope_entry: ScopeEntry | None, hostname: str) -> Environment:
    """Infer environment from the scope entry, falling back to the hostname.

    Marked as INFERRED wherever it is used, because a hostname marker such as
    ``staging.`` is a strong hint, not a statement of fact.
    """
    if scope_entry is not None and scope_entry.environment is not Environment.UNKNOWN:
        return scope_entry.environment
    lowered = hostname.lower()
    for marker, env in (
        ("prod", Environment.PRODUCTION),
        ("staging", Environment.STAGING),
        ("stage", Environment.STAGING),
        ("uat", Environment.STAGING),
        ("dev", Environment.DEVELOPMENT),
        ("test", Environment.DEVELOPMENT),
        ("qa", Environment.DEVELOPMENT),
    ):
        if marker in lowered:
            return env
    return Environment.UNKNOWN


class ScanRunner:
    """Executes one scan run for one organization."""

    def __init__(
        self,
        session: Session,
        *,
        organization_id: str,
        created_by_user_id: str | None = None,
        trigger: ScanTrigger = ScanTrigger.MANUAL,
        label: str | None = None,
        enable_ct: bool = False,
        enable_subdomain_discovery: bool = True,
    ) -> None:
        self.session = session
        self.organization_id = organization_id
        self.created_by_user_id = created_by_user_id
        self.trigger = trigger
        self.label = label
        self.enable_ct = enable_ct
        self.enable_subdomain_discovery = enable_subdomain_discovery
        self.guard = ScopeGuard(session, organization_id)
        self.scanner = get_port_scanner()
        self._port_cache: dict[str, list[int]] = {}

    # -- lifecycle ---------------------------------------------------------

    def create_scan(self, scope_entry_ids: list[str] | None = None) -> Scan:
        """Create the Scan row in QUEUED state."""
        scan = Scan(
            organization_id=self.organization_id,
            status=ScanStatus.QUEUED,
            trigger=self.trigger,
            label=self.label,
            started_at=utcnow(),
            created_by_user_id=self.created_by_user_id,
            scope_entry_ids=scope_entry_ids or [],
            scanner_backend=self.scanner.name,
        )
        self.session.add(scan)
        self.session.flush()
        return scan

    def run(self, scan: Scan, scope_entry_ids: list[str] | None = None) -> ScanOutcome:
        """Execute the scan end to end."""
        started = time.perf_counter()
        scan.status = ScanStatus.RUNNING
        self.session.flush()

        try:
            outcome = self._run_inner(scan, scope_entry_ids)
        except Exception as exc:  # noqa: BLE001 - a scan must never crash the caller
            scan.status = ScanStatus.FAILED
            scan.error_message = truncate(f"{type(exc).__name__}: {exc}", 2000)
            scan.finished_at = utcnow()
            self.session.flush()
            return ScanOutcome(
                scan_id=scan.id,
                status=ScanStatus.FAILED,
                errors=[scan.error_message or "unknown error"],
                duration_seconds=round(time.perf_counter() - started, 3),
            )

        scan.status = ScanStatus.COMPLETED
        scan.finished_at = utcnow()
        outcome.duration_seconds = round(time.perf_counter() - started, 3)
        self.session.flush()
        return outcome

    # -- internals ---------------------------------------------------------

    def _authorized_entries(self, scope_entry_ids: list[str] | None) -> list[ScopeEntry]:
        entries = self.guard.authorized_targets()
        if scope_entry_ids:
            wanted = set(scope_entry_ids)
            entries = [e for e in entries if e.id in wanted]
        return entries

    def _run_inner(self, scan: Scan, scope_entry_ids: list[str] | None) -> ScanOutcome:
        outcome = ScanOutcome(scan_id=scan.id, status=ScanStatus.RUNNING)

        entries = self._authorized_entries(scope_entry_ids)
        if not entries:
            outcome.errors.append(
                "no authorized, unexpired scope entries matched; nothing was scanned"
            )
            scan.error_message = outcome.errors[0]
            return outcome

        scan.scope_entry_ids = [e.id for e in entries]

        plans, rejections = self._build_plans(entries)
        outcome.blocked = [r.as_dict() for r in rejections]
        outcome.targets_blocked = len(rejections)

        scan.targets_requested = len(plans) + len(rejections)
        scan.blocked_targets = outcome.blocked

        if not plans:
            outcome.errors.append(
                "every candidate target was refused by the safety floor; see blocked targets"
            )
            scan.error_message = outcome.errors[0]
            return outcome

        previous_scan = self._previous_completed_scan(scan.id)
        all_changes: list[ExposureChange] = []

        for plan in plans:
            try:
                target_outcome = self._scan_target(scan, plan)
            except Exception as exc:  # noqa: BLE001 - isolate per-target failures
                outcome.errors.append(
                    f"{plan.hostname}: {type(exc).__name__}: {truncate(str(exc), 300)}"
                )
                continue

            outcome.assets_found += target_outcome["assets"]
            outcome.services_found += target_outcome["services"]
            outcome.observations_recorded += target_outcome["observations"]
            outcome.targets_scanned += 1
            all_changes.extend(target_outcome["changes"])

        # Discovery: names proposed by DNS/CT are re-checked against scope.
        if self.enable_subdomain_discovery or self.enable_ct:
            discovered = self._discover_sub_assets(scan, entries)
            for name, source in discovered:
                decision = self.guard.check(name)
                if not decision.allowed or decision.match is None:
                    outcome.blocked.append(
                        {
                            "target": name,
                            "reason": (
                                decision.rejection.reason.value
                                if decision.rejection
                                else TargetRejectionReason.OUT_OF_SCOPE.value
                            ),
                            "detail": (
                                f"discovered via {source} but not authorized for assessment"
                            ),
                        }
                    )
                    outcome.targets_blocked += 1
                    continue

                if self._asset_exists(name):
                    continue

                plan = TargetPlan(
                    hostname=name,
                    addresses=self._resolve_for_scan(name),
                    scope_entry=decision.match.entry,
                    discovered_via=source,
                    discovered_from=source,
                )
                if not plan.addresses:
                    continue
                try:
                    target_outcome = self._scan_target(scan, plan, is_new_discovery=True)
                except Exception as exc:  # noqa: BLE001
                    outcome.errors.append(f"{name}: {truncate(str(exc), 300)}")
                    continue
                outcome.assets_found += target_outcome["assets"]
                outcome.services_found += target_outcome["services"]
                outcome.observations_recorded += target_outcome["observations"]
                all_changes.extend(target_outcome["changes"])

        # Detect changes and evaluate findings on the completed observations.
        from veyl_analyzer.engine import analyze_scan
        from veyl_correlation.changes import detect_changes

        change_result = detect_changes(self.session, scan=scan, previous_scan=previous_scan)
        all_changes.extend(change_result.changes)

        analyze_result = analyze_scan(self.session, scan=scan)
        scan.findings_created = analyze_result.findings_created

        # Correlate attack paths after findings exist.
        from veyl_correlation.attack_paths import correlate_attack_paths
        from veyl_correlation.graph import rebuild_graph

        rebuild_graph(self.session, organization_id=self.organization_id)
        correlate_attack_paths(self.session, organization_id=self.organization_id, scan=scan)

        outcome.assets_found = len(
            {
                obs.asset_id
                for obs in self.session.query(Observation)
                .filter(Observation.scan_id == scan.id, Observation.asset_id.isnot(None))
                .all()
            }
        )
        scan.assets_found = outcome.assets_found
        scan.services_found = outcome.services_found
        scan.targets_scanned = outcome.targets_scanned
        scan.targets_blocked = outcome.targets_blocked
        scan.changes_detected = len(all_changes)
        scan.blocked_targets = outcome.blocked
        self.session.flush()

        return outcome

    def _previous_completed_scan(self, current_scan_id: str) -> Scan | None:
        from sqlalchemy import select

        stmt = (
            select(Scan)
            .where(
                Scan.organization_id == self.organization_id,
                Scan.status == ScanStatus.COMPLETED,
                Scan.id != current_scan_id,
            )
            .order_by(Scan.finished_at.desc())
            .limit(1)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def _build_plans(
        self, entries: list[ScopeEntry]
    ) -> tuple[list[TargetPlan], list[TargetRejection]]:
        """Turn scope entries into validated target plans."""
        plans: list[TargetPlan] = []
        rejections: list[TargetRejection] = []
        seen: set[str] = set()

        for entry in entries:
            try:
                validated = validate_target(entry.domain)
            except UnsafeTargetError as exc:
                rejections.append(exc.rejection)
                continue

            if validated.hostname in seen:
                continue
            seen.add(validated.hostname)

            # Belt and braces: re-check scope against the resolved addresses.
            decision = self.guard.check(validated.hostname, resolved_addresses=list(validated.addresses))
            if not decision.allowed:
                if decision.rejection:
                    rejections.append(decision.rejection)
                continue

            plans.append(
                TargetPlan(
                    hostname=validated.hostname,
                    addresses=validated.addresses,
                    scope_entry=entry,
                )
            )
        return plans, rejections

    def _resolve_for_scan(self, hostname: str) -> tuple[str, ...]:
        try:
            return validate_target(hostname).addresses
        except UnsafeTargetError:
            return ()

    def _asset_exists(self, asset_key: str) -> bool:
        from sqlalchemy import select

        stmt = select(Asset.id).where(
            Asset.organization_id == self.organization_id, Asset.asset_key == asset_key
        )
        return self.session.execute(stmt).scalar_one_or_none() is not None

    def _ports_for(self, entry: ScopeEntry | None) -> list[int]:
        """Ports to scan for a given scope entry."""
        allowed = settings.allowed_ports
        if entry is not None and entry.allow_port_override:
            # An operator opted this target into a wider sweep. Still bounded by
            # the global maximum so an override cannot become a full 65k scan.
            return sorted(set(allowed) | set(range(1, 1025)))
        return allowed

    def _discover_sub_assets(self, scan: Scan, entries: list[ScopeEntry]) -> list[tuple[str, str]]:
        """Run discovery collectors and return (name, source) candidate pairs."""
        found: dict[str, str] = {}
        for entry in entries[:10]:
            if self.enable_ct and len(entry.domain.split(".")) >= 2:
                ct = TlsCollector  # placeholder to keep import graph obvious
                from veyl_scanner.tls import CertificateTransparencyCollector

                result = CertificateTransparencyCollector().collect(
                    ScanRequest(
                        hostname=entry.domain,
                        addresses=(),
                        ports=(),
                        organization_id=self.organization_id,
                        timeout_seconds=settings.scan_timeout_seconds,
                    )
                )
                for name in result.discovered_names:
                    found.setdefault(name, "certificate_transparency")
                del ct

            if self.enable_subdomain_discovery:
                dns_result = DnsCollector(discover_subdomains=True).collect(
                    ScanRequest(
                        hostname=entry.domain,
                        addresses=(),
                        ports=(),
                        organization_id=self.organization_id,
                        timeout_seconds=min(settings.scan_timeout_seconds, 3.0),
                    )
                )
                for name in dns_result.discovered_names:
                    found.setdefault(name, "dns_wordlist")
        return sorted(found.items())

    # -- the actual probing ------------------------------------------------

    def _scan_target(
        self, scan: Scan, plan: TargetPlan, *, is_new_discovery: bool = False
    ) -> dict[str, Any]:
        """Probe one target and persist observations, services and assets."""
        entry = plan.scope_entry
        ports = self._ports_for(entry)
        valid_ports = [p for p in ports if validate_port(p) is None]

        request = ScanRequest(
            hostname=plan.hostname,
            addresses=plan.addresses,
            ports=tuple(valid_ports),
            organization_id=self.organization_id,
            scope_entry_id=entry.id,
            timeout_seconds=settings.scan_timeout_seconds,
            user_agent=settings.scan_user_agent,
            follow_redirects=False,
        )

        observations: list[ObservationPayload] = []

        # 1. Port sweep.
        port_results = self.scanner.scan_ports(request, valid_ports)
        open_ports = [r.port for r in port_results if r.state == "open"]
        observations.append(
            ObservationPayload(
                kind="port_scan",
                subject=plan.hostname,
                asset_key=plan.hostname,
                data={
                    "hostname": plan.hostname,
                    "addresses": list(plan.addresses),
                    "scanner": self.scanner.name,
                    "ports_scanned": len(valid_ports),
                    "open_ports": open_ports,
                    "results": [
                        {"port": r.port, "state": r.state, "latency_ms": r.latency_ms}
                        for r in port_results
                        if r.state == "open"
                    ],
                },
                confidence=Confidence.HIGH,
                summary=f"{len(open_ports)} open port(s): {', '.join(map(str, open_ports)) or 'none'}",
            )
        )

        request = ScanRequest(
            hostname=request.hostname,
            addresses=request.addresses,
            ports=tuple(open_ports),
            organization_id=self.organization_id,
            scope_entry_id=entry.id,
            timeout_seconds=settings.scan_timeout_seconds,
            user_agent=settings.scan_user_agent,
            follow_redirects=False,
        )

        # 2. DNS.
        dns_result = DnsCollector(discover_subdomains=False).collect(request)
        observations.extend(dns_result.observations)

        # 3. Service fingerprinting on the open ports.
        from veyl_scanner.fingerprint import fingerprint_services

        fingerprints = fingerprint_services(
            plan.hostname, plan.addresses[0], open_ports, request.timeout_seconds
        )
        for fingerprint in fingerprints:
            observations.append(
                ObservationPayload(
                    kind="service_fingerprint",
                    subject=f"{plan.hostname}:{fingerprint.port}",
                    asset_key=plan.hostname,
                    data=fingerprint.as_dict(),
                    confidence=fingerprint.confidence,
                    summary=(
                        f"TCP/{fingerprint.port} {fingerprint.service_name}"
                        + (f" ({fingerprint.product} {fingerprint.version})" if fingerprint.product else "")
                    ),
                )
            )

        # 4. TLS.
        if any(p in (443, 8443) for p in open_ports):
            observations.extend(TlsCollector().collect(request).observations)

        # 5. HTTP.
        if any(p in (80, 443, 8080, 8443) or p > 1024 for p in open_ports):
            http_collector = HttpCollector(
                probe_paths=True,
                discover_paths=True,
                validate_hook=lambda h: self.guard.check(h).allowed,
            )
            observations.extend(http_collector.collect(request).observations)

        # Persist asset + everything observed.
        asset = self._upsert_asset(scan, plan, open_ports, fingerprints, is_new_discovery)
        for payload in observations:
            self._persist_observation(scan, asset, payload)

        self._upsert_services(asset, fingerprints, plan)
        self._upsert_certificates(asset, observations)
        self._capture_snapshot(scan, asset, plan, fingerprints, observations)

        return {
            "assets": 1,
            "services": len([f for f in fingerprints if f.service_name != "unknown"]),
            "observations": len(observations),
            "changes": [],
            "asset_id": asset.id,
        }

    def _upsert_asset(
        self,
        scan: Scan,
        plan: TargetPlan,
        open_ports: list[int],
        fingerprints: list[Any],
        is_new_discovery: bool,
    ) -> Asset:
        from sqlalchemy import select

        entry = plan.scope_entry
        asset_key = plan.hostname

        stmt = select(Asset).where(
            Asset.organization_id == self.organization_id, Asset.asset_key == asset_key
        )
        asset = self.session.execute(stmt).scalar_one_or_none()

        hostname_parts = asset_key.split(".")
        is_subdomain = len(hostname_parts) > 2 and not _is_ip(asset_key)
        asset_type = AssetType.IP if _is_ip(asset_key) else (
            AssetType.SUBDOMAIN if is_subdomain else AssetType.DOMAIN
        )

        # Refine the type from what is actually listening, if anything.
        for fingerprint in fingerprints:
            mapped = _SERVICE_ASSET_TYPE.get(fingerprint.service_name)
            if mapped in (AssetType.DATABASE, AssetType.APPLICATION):
                asset_type = mapped
                break

        now = utcnow()
        if asset is None:
            asset = Asset(
                organization_id=self.organization_id,
                asset_key=asset_key,
                hostname=None if _is_ip(asset_key) else asset_key,
                ip_address=plan.addresses[0] if _is_ip(asset_key) else plan.addresses[0],
                domain=".".join(hostname_parts[-2:]) if not _is_ip(asset_key) else None,
                asset_type=asset_type,
                environment=infer_environment(entry, asset_key),
                status="ACTIVE",
                internet_exposed=bool(open_ports),
                authorization_status=entry.authorization_status,
                discovery_source=(plan.discovered_via if is_new_discovery else "scope_scan"),
                source_provenance=Provenance.OBSERVED,
                first_seen=now,
                last_seen=now,
                scope_entry_id=entry.id,
                # Business context starts conservative and marked INFERRED.
                business_criticality=BusinessCriticality.LOW,
                data_classification=DataClassification.PUBLIC,
                owner=entry.asset_owner,
                context_source=Provenance.INFERRED,
            )
            self.session.add(asset)
            self.session.flush()

            self.session.add(
                AssetContext(
                    organization_id=self.organization_id,
                    asset_id=asset.id,
                    business_criticality=BusinessCriticality.LOW,
                    data_classification=DataClassification.PUBLIC,
                    owner=entry.asset_owner,
                    context_source=Provenance.INFERRED,
                    context_confidence=Confidence.LOW,
                )
            )
        else:
            asset.last_seen = now
            asset.ip_address = plan.addresses[0]
            asset.internet_exposed = asset.internet_exposed or bool(open_ports)
            if asset.status != "ACTIVE":
                asset.status = "ACTIVE"

        self.session.flush()
        return asset

    def _persist_observation(self, scan: Scan, asset: Asset, payload: ObservationPayload) -> Observation:
        sanitized = deep_sanitize_json(payload.data)
        observation = Observation(
            organization_id=self.organization_id,
            scan_id=scan.id,
            asset_id=asset.id,
            kind=payload.kind,
            subject=truncate(payload.subject, 200),
            provenance=payload.provenance,
            confidence=payload.confidence,
            data=sanitized,
            observed_at=payload.observed_at or utcnow(),
        )
        self.session.add(observation)
        return observation

    def _upsert_services(self, asset: Asset, fingerprints: list[Any], plan: TargetPlan) -> None:
        from sqlalchemy import select

        now = utcnow()
        for fingerprint in fingerprints:
            stmt = select(Service).where(
                Service.asset_id == asset.id,
                Service.port == fingerprint.port,
                Service.protocol == "tcp",
            )
            service = self.session.execute(stmt).scalar_one_or_none()
            if service is None:
                service = Service(
                    organization_id=self.organization_id,
                    asset_id=asset.id,
                    port=fingerprint.port,
                    protocol="tcp",
                    state="open",
                    first_seen=now,
                    last_seen=now,
                )
                self.session.add(service)

            service.service_name = fingerprint.service_name
            service.product = fingerprint.product
            service.version = fingerprint.version
            service.banner = truncate(fingerprint.banner, 2000)
            service.fingerprint_confidence = fingerprint.confidence
            service.fingerprint_evidence = deep_sanitize_json(fingerprint.evidence)
            service.is_encrypted = fingerprint.port in _ENCRYPTED_PORTS or fingerprint.service_name in {
                "https",
                "smtps",
                "imaps",
                "pop3s",
                "ldaps",
            }
            service.is_administrative = (
                fingerprint.port in _ADMIN_PORTS
                or "admin" in (fingerprint.service_name or "").lower()
            )
            service.is_database = (
                fingerprint.port in _DATABASE_PORTS
                or fingerprint.service_name in _SERVICE_ASSET_TYPE
                and _SERVICE_ASSET_TYPE.get(fingerprint.service_name) is AssetType.DATABASE
            )
            service.internet_reachable = True
            service.last_seen = now

        self.session.flush()

    def _upsert_certificates(self, asset: Asset, observations: list[ObservationPayload]) -> None:
        from sqlalchemy import select

        now = utcnow()
        for payload in observations:
            if payload.kind != "tls_certificate":
                continue
            data = payload.data
            fingerprint = data.get("fingerprint_sha256")
            if not fingerprint:
                continue

            stmt = select(Certificate).where(
                Certificate.asset_id == asset.id,
                Certificate.fingerprint_sha256 == fingerprint,
                Certificate.port == data.get("port", 443),
            )
            cert = self.session.execute(stmt).scalar_one_or_none()

            not_before = _parse_dt(data.get("not_before"))
            not_after = _parse_dt(data.get("not_after"))
            if not_before is None or not_after is None:
                continue

            if cert is None:
                cert = Certificate(
                    organization_id=self.organization_id,
                    asset_id=asset.id,
                    port=data.get("port", 443),
                    fingerprint_sha256=fingerprint,
                    subject=truncate(str(data.get("subject", "")), 500),
                    issuer=truncate(str(data.get("issuer", "")), 500),
                    not_before=not_before,
                    not_after=not_after,
                    first_seen=now,
                    last_seen=now,
                )
                self.session.add(cert)

            cert.serial_number = truncate(str(data.get("serial_number", "")), 128)
            cert.san = data.get("san", [])[:200]
            cert.is_self_signed = bool(data.get("is_self_signed"))
            cert.chain_valid = data.get("chain_valid")
            cert.hostname_valid = data.get("hostname_valid")
            cert.tls_version = data.get("tls_version")
            cert.cipher_suite = data.get("cipher_suite")
            cert.signature_algorithm = data.get("signature_algorithm")
            cert.key_size = data.get("key_size")
            cert.last_seen = now

        self.session.flush()

    def _capture_snapshot(
        self,
        scan: Scan,
        asset: Asset,
        plan: TargetPlan,
        fingerprints: list[Any],
        observations: list[ObservationPayload],
    ) -> None:
        """Persist the asset's normalized state at the end of this scan."""
        port_scan = next((o for o in observations if o.kind == "port_scan"), None)
        open_ports = port_scan.data.get("open_ports", []) if port_scan else []

        service_signatures = {
            str(f.port): f"{f.service_name}|{f.product or ''}|{f.version or ''}"
            for f in fingerprints
        }

        tls_obs = next((o for o in observations if o.kind == "tls_certificate"), None)
        http_obs = next((o for o in observations if o.kind == "http_response"), None)
        header_obs = next((o for o in observations if o.kind == "http_security_headers"), None)
        dns_obs = next((o for o in observations if o.kind == "dns_a"), None)

        state: dict[str, Any] = {
            "ports": sorted(open_ports),
            "services": service_signatures,
            "certificate": (
                {
                    "fingerprint": tls_obs.data.get("fingerprint_sha256"),
                    "not_after": tls_obs.data.get("not_after"),
                    "issuer": tls_obs.data.get("issuer"),
                    "subject": tls_obs.data.get("subject"),
                    "tls_version": tls_obs.data.get("tls_version"),
                    "is_self_signed": tls_obs.data.get("is_self_signed"),
                }
                if tls_obs
                else None
            ),
            "http": (
                {
                    "status_code": http_obs.data.get("status_code"),
                    "server": (header_obs.data.get("headers", {}) or {}).get("server")
                    if header_obs
                    else None,
                }
                if http_obs
                else None
            ),
            "security_headers": (
                {
                    k: v
                    for k, v in (header_obs.data.get("headers", {}) or {}).items()
                    if k
                    in {
                        "strict-transport-security",
                        "content-security-policy",
                        "x-content-type-options",
                        "x-frame-options",
                        "referrer-policy",
                        "permissions-policy",
                        "access-control-allow-origin",
                        "access-control-allow-credentials",
                    }
                }
                if header_obs
                else None
            ),
            "dns_a": sorted(dns_obs.data.get("records", [])) if dns_obs else None,
            "tech": sorted(
                f"{t.get('product')}|{t.get('version') or ''}"
                for o in observations
                if o.kind == "http_tech"
                for t in o.data.get("technologies", [])
            ),
            "internet_exposed": bool(open_ports),
        }

        sanitized_state = deep_sanitize_json(state)
        snapshot = AssetSnapshot(
            organization_id=self.organization_id,
            scan_id=scan.id,
            asset_id=asset.id,
            captured_at=utcnow(),
            state=sanitized_state,
            state_hash=checksum(sanitized_state),
            port_states={str(p): "open" for p in open_ports},
            service_signatures=service_signatures,
        )
        self.session.add(snapshot)
        self.session.flush()


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _parse_dt(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp from an observation payload."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
