"""AcmePay demo: run the Day 1 -> Day 7 exposure-change story end to end.

This script exists to prove the product's central claim: that Veyl tells you what
*changed* about your exposure and why it matters, rather than just listing
open ports. It runs two real scans against two profiles of the bundled demo
service and prints the differences Veyl detected between them.

    python demo/scripts/acmepay_scenario.py

Both scans hit a real HTTP server on a real TCP port. Nothing is simulated.
"""

from __future__ import annotations

import os
import socket
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for path in ("apps/api", "packages/rules", "services/scanner", "services/analyzer",
             "services/correlation", "demo/targets"):
    sys.path.insert(0, os.path.join(ROOT, path))

os.environ.setdefault("VEYL_DATABASE_URL", "sqlite:///./demo_scenario.db")
os.environ.setdefault("VEYL_SECRET_KEY", "acmepay-demo-secret-key-not-for-production")
os.environ.setdefault("VEYL_ALLOW_PRIVATE_TARGETS", "true")
os.environ.setdefault("VEYL_ENV", "development")

from acmepay_service import build_server  # noqa: E402
from veyl_analyzer.engine import rescore_findings  # noqa: E402
from veyl_correlation.attack_paths import correlate_attack_paths  # noqa: E402
from veyl_correlation.graph import rebuild_graph  # noqa: E402
from veyl_scanner.runner import ScanRunner  # noqa: E402

from veyl_api.db.base import Base, utcnow  # noqa: E402
from veyl_api.db.session import SessionLocal, engine  # noqa: E402
from veyl_api.enums import (  # noqa: E402
    AssetOwner,
    AuthorizationStatus,
    BusinessCriticality,
    BusinessFunction,
    DataClassification,
    Environment,
    Provenance,
    ScanTrigger,
)
from veyl_api.models import (  # noqa: E402
    Asset,
    AssetContext,
    ExposureChange,
    Finding,
    Organization,
    ScopeEntry,
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class DemoServer:
    """The AcmePay service, restartable with a different profile."""

    def __init__(self) -> None:
        self.port = _free_port()
        self._httpd = None
        self._thread: threading.Thread | None = None

    def start(self, profile: str) -> None:
        self._httpd = build_server(self.port, profile, verbose=False)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def _scan(session, org_id: str, scope_id: str, port: int, label: str):
    runner = ScanRunner(
        session,
        organization_id=org_id,
        trigger=ScanTrigger.SCHEDULED,
        label=label,
        enable_ct=False,
        enable_subdomain_discovery=False,
        port_override=[port],
    )
    scan = runner.create_scan([scope_id])
    session.commit()
    outcome = runner.run(scan, [scope_id])
    session.commit()
    return scan, outcome


def _describe_asset(session, org_id: str) -> Asset | None:
    return (
        session.query(Asset)
        .filter(Asset.organization_id == org_id)
        .order_by(Asset.created_at)
        .first()
    )


def main() -> int:
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    server = DemoServer()

    try:
        org = Organization(
            name="AcmePay",
            slug="acmepay",
            primary_domain="acmepay.example",
            industry="Financial Services",
        )
        session.add(org)
        session.commit()

        scope = ScopeEntry(
            organization_id=org.id,
            domain="127.0.0.1",
            environment=Environment.PRODUCTION,
            asset_owner=AssetOwner.ENGINEERING,
            authorization_status=AuthorizationStatus.AUTHORIZED,
            authorized_by="AcmePay security team",
            authorized_at=utcnow(),
            notes="AcmePay payments API — authorized for continuous assessment.",
            allow_port_override=True,
        )
        session.add(scope)
        session.commit()

        print("=" * 78)
        print("AcmePay continuous exposure scenario")
        print("=" * 78)

        # ---------------------------------------------------------------
        # Day 1 — the well-configured baseline.
        # ---------------------------------------------------------------
        print("\nDAY 1 — 'nginx/1.18.0', correct security headers, no admin surface")
        server.start("day1")
        day1_scan, day1_outcome = _scan(
            session, org.id, scope.id, server.port, "Day 1 baseline"
        )
        _apply_context(session, org.id)
        day1_findings = _findings(session, org.id)
        print(f"  scan {day1_scan.id[:8]}  observations={day1_outcome.observations_recorded}"
              f"  findings={len(day1_findings)}")
        for finding in day1_findings:
            print(f"    [{finding.severity.value:8}] {finding.risk_score:5.1f} "
                  f"{finding.rule_id:14} {finding.title[:50]}")
        server.stop()

        # ---------------------------------------------------------------
        # Day 7 — a regression: admin surface appears, a security header is
        # removed, and CORS is loosened. This is the thing we must catch.
        # ---------------------------------------------------------------
        print("\nDAY 7 — admin console now reachable, clickjacking protection removed,")
        print("        wildcard CORS with credentials")
        server.start("day7")
        day7_scan, day7_outcome = _scan(
            session, org.id, scope.id, server.port, "Day 7 regression"
        )
        print(f"  scan {day7_scan.id[:8]}  observations={day7_outcome.observations_recorded}")

        # ---------------------------------------------------------------
        # What changed between the two scans.
        # ---------------------------------------------------------------
        changes = list(
            session.query(ExposureChange)
            .filter(
                ExposureChange.organization_id == org.id,
                ExposureChange.scan_id == day7_scan.id,
            )
            .order_by(ExposureChange.risk_score.desc())
            .all()
        )
        print(f"\nCHANGES DETECTED since the previous scan: {len(changes)}")
        risk_increasing = [c for c in changes if c.is_risk_increasing]
        print(f"  risk-increasing: {len(risk_increasing)}")
        for change in changes:
            flag = "RISK UP" if change.is_risk_increasing else "       "
            print(f"    [{flag}] {change.significance.value:11} {change.risk_score:5.1f} "
                  f"{change.change_type.value}")
            print(f"               {change.subject[:88]}")
            if change.security_significance:
                print(f"               why: {change.security_significance[:88]}")

        # ---------------------------------------------------------------
        # Current findings and the prioritisation a customer would act on.
        # ---------------------------------------------------------------
        rescore_findings(session, organization_id=org.id)
        session.commit()
        active = _findings(session, org.id)
        print(f"\nCURRENT FINDINGS: {len(active)}")
        for finding in sorted(active, key=lambda f: -f.risk_score):
            print(f"    [{finding.severity.value:8}] {finding.risk_score:5.1f} "
                  f"{finding.rule_id:14} {finding.title[:52]}")

        if active:
            top = max(active, key=lambda f: f.risk_score)
            from veyl_analyzer.risk import default_priority_for
            print(f"\nTOP PRIORITY: {default_priority_for(top.risk_score)} — {top.title}")
            print(f"  {top.risk_explanation}")

        # ---------------------------------------------------------------
        # Correlated attack paths, with the POTENTIAL-only discipline.
        # ---------------------------------------------------------------
        graph = rebuild_graph(session, organization_id=org.id)
        paths = correlate_attack_paths(session, organization_id=org.id, scan=day7_scan)
        session.commit()
        print(f"\nATTACK-SURFACE GRAPH: {graph.stats['nodes']} nodes, {graph.stats['edges']} edges")
        print(f"ATTACK PATHS: {len(paths)} (all POTENTIAL unless a check verified otherwise)")
        for path in paths:
            print(f"    [{path.state.value}] {path.risk_score:5.1f} {path.name[:70]}")
            print(f"      limitations: {path.limitations[:100]}...")

        # ---------------------------------------------------------------
        # Summary of the story.
        # ---------------------------------------------------------------
        new_findings = [
            f for f in active
            if f.first_scan_id == day7_scan.id
        ]
        print("\n" + "=" * 78)
        print(f"STORY: Day 1 had {len(day1_findings)} finding(s); after the Day 7 change "
              f"there are {len(active)}.")
        print(f"       {len(risk_increasing)} risk-increasing change(s) were correlated to "
              f"business context.")
        print(f"       {len(new_findings)} finding(s) first appeared in the Day 7 scan.")
        print("=" * 78)
        return 0
    finally:
        session.close()
        server.stop()


def _apply_context(session, organization_id: str) -> None:
    """AcmePay tells Veyl what this asset is. Marked USER_PROVIDED.

    Note the ``internet_exposed`` assignment. Veyl learned that the host is
    *reachable* by scanning it, but only AcmePay can say that the payments API
    is published to the internet. That distinction is the reason the field is
    not set by the scanner: a scan proves reachability from where it ran, and
    nothing more.
    """
    assets = session.query(Asset).filter(Asset.organization_id == organization_id).all()
    for asset in assets:
        asset.business_criticality = BusinessCriticality.CRITICAL
        asset.data_classification = DataClassification.CONFIDENTIAL
        asset.business_function = BusinessFunction.PAYMENTS
        asset.environment = Environment.PRODUCTION
        # Declared by the organization, not derived from the scan.
        asset.internet_exposed = True
        asset.context_source = Provenance.USER_PROVIDED
        if asset.context is None:
            session.add(
                AssetContext(
                    organization_id=organization_id,
                    asset_id=asset.id,
                    business_criticality=BusinessCriticality.CRITICAL,
                    data_classification=DataClassification.CONFIDENTIAL,
                    business_function=BusinessFunction.PAYMENTS,
                    environment=Environment.PRODUCTION,
                    provenance=Provenance.USER_PROVIDED,
                    source="AcmePay security team",
                    business_description=(
                        "Primary payments API. Processes card authorizations and settlements."
                    ),
                    notes="Classified by AcmePay, not inferred by Veyl.",
                )
            )
    session.commit()
    rescore_findings(session, organization_id=organization_id)
    session.commit()


def _findings(session, organization_id: str) -> list[Finding]:
    from veyl_api.enums import ACTIVE_FINDING_STATUSES

    return list(
        session.query(Finding)
        .filter(
            Finding.organization_id == organization_id,
            Finding.status.in_([s.value for s in ACTIVE_FINDING_STATUSES]),
        )
        .all()
    )


if __name__ == "__main__":
    raise SystemExit(main())
