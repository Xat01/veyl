"""Run the scanner -> analyzer -> correlation pipeline against a local target.

Used for verification during development and as a smoke test. It is not part of
the product surface.

By default the script starts the AcmePay demo service on a background thread and
scans that, so the result is deterministic and does not depend on whatever else
happens to be listening on the developer's machine. Pass ``--external`` to scan
a host you are actually authorized to scan instead.

    python scripts/pipeline_smoke.py                  # scan the bundled demo
    python scripts/pipeline_smoke.py --profile day7   # pick a demo profile
    python scripts/pipeline_smoke.py --external 10.0.0.5
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in ("apps/api", "packages/rules", "services/scanner", "services/analyzer", "services/correlation"):
    sys.path.insert(0, os.path.join(ROOT, path))

os.environ.setdefault("VEYL_DATABASE_URL", "sqlite:///./smoke.db")
os.environ.setdefault("VEYL_SECRET_KEY", "smoke-test-secret-key-not-for-production")
os.environ.setdefault("VEYL_ALLOW_PRIVATE_TARGETS", "true")
os.environ.setdefault("VEYL_ENV", "development")

from veyl_analyzer.engine import rescore_findings  # noqa: E402
from veyl_correlation.attack_paths import correlate_attack_paths  # noqa: E402
from veyl_correlation.graph import rebuild_graph  # noqa: E402
from veyl_scanner.runner import ScanRunner  # noqa: E402

from veyl_api.db.base import utcnow  # noqa: E402
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


def _start_demo(profile: str) -> tuple[int, threading.Thread, object]:
    """Start the bundled demo target on an ephemeral port, in-process."""
    sys.path.insert(0, os.path.join(ROOT, "demo", "targets"))
    from acmepay_service import build_server  # type: ignore[import-not-found]

    port = _free_port()
    httpd = build_server(port, profile, verbose=False)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return port, thread, httpd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Veyl pipeline smoke test")
    parser.add_argument("--profile", default="day7",
                        choices=["day1", "day5", "day7"])
    parser.add_argument("--external", default=None,
                        help="scan this host instead of the bundled demo target")
    parser.add_argument("--port", type=int, default=None,
                        help="restrict the port sweep to this single port")
    args = parser.parse_args(argv)

    httpd = None
    if args.external:
        target = args.external
        target_port = args.port or 443
        print(f"scanning external target {target} (you must be authorized to do this)")
    else:
        target_port, _thread, httpd = _start_demo(args.profile)
        target = "127.0.0.1"
        print(f"started bundled AcmePay target on {target}:{target_port} "
              f"[profile={args.profile}]")

    # The demo target listens on an ephemeral port, so the sweep must be told to
    # look at exactly that port. Settings are read once at import time by the
    # runner, so overriding the environment here and reloading the module is not
    # enough; the restriction is applied by narrowing the scope entry below,
    # which is also closer to how an operator would really do it.
    restrict_to_demo_port = not args.external

    from veyl_api.db.base import create_all, drop_all

    drop_all(engine)
    create_all(engine)

    session = SessionLocal()
    try:
        org = Organization(name="AcmePay", slug="acmepay",
                           primary_domain="acmepay.example", industry="Financial Services")
        session.add(org)
        session.commit()

        scope = ScopeEntry(
            organization_id=org.id,
            domain=target,
            environment=Environment.PRODUCTION,
            asset_owner=AssetOwner.ENGINEERING,
            authorization_status=AuthorizationStatus.AUTHORIZED,
            authorized_by="smoke test",
            authorized_at=utcnow(),
            notes="Local smoke-test target.",
            # The demo target listens on an ephemeral port. Widening the sweep
            # for this target is an explicit, recorded scope decision rather
            # than something the calling code can do silently.
            allow_port_override=restrict_to_demo_port,
        )
        session.add(scope)
        session.commit()

        runner = ScanRunner(
            session,
            organization_id=org.id,
            trigger=ScanTrigger.MANUAL,
            label="smoke run",
            enable_ct=False,
            enable_subdomain_discovery=False,
            # Pass the demo port explicitly so the run is fast and the output is
            # about the demo service rather than whatever else is listening.
            port_override=[target_port] if restrict_to_demo_port else None,
        )
        scan = runner.create_scan([scope.id])
        session.commit()

        print(f"scan {scan.id[:8]} starting against {target}")
        outcome = runner.run(scan, [scope.id])
        session.commit()
        session.refresh(scan)

        print(f"  status            : {scan.status.value}")
        print(f"  targets scanned   : {outcome.targets_scanned}")
        print(f"  targets blocked   : {outcome.targets_blocked}")
        print(f"  observations      : {outcome.observations_recorded}")
        print(f"  duration          : {outcome.duration_seconds}s")
        if outcome.errors:
            print(f"  errors            : {outcome.errors[:3]}")

        # Business context matters to the risk model, so set it the way a real
        # customer would before findings are scored.
        _apply_business_context(session, org.id)

        findings = session.query(Finding).filter(Finding.organization_id == org.id).all()
        print(f"  findings          : {len(findings)}")
        for finding in sorted(findings, key=lambda f: -f.risk_score)[:12]:
            print(
                f"    [{finding.severity.value:8}] {finding.risk_score:5.1f} "
                f"{finding.rule_id:14} {finding.title[:56]}"
            )

        changes = session.query(ExposureChange).filter(
            ExposureChange.organization_id == org.id
        ).all()
        print(f"  exposure changes  : {len(changes)}")

        graph = rebuild_graph(session, organization_id=org.id)
        print(f"  graph             : {graph.stats}")

        paths = correlate_attack_paths(session, organization_id=org.id, scan=scan)
        print(f"  attack paths      : {len(paths)}")
        for path in paths:
            print(f"    [{path.state.value}] {path.risk_score:5.1f} {path.name[:62]}")

        session.commit()
        return 0
    finally:
        session.close()
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()


def _apply_business_context(session, organization_id: str) -> None:
    """Attach owner-established context, marked as USER_PROVIDED.

    This is what makes the risk model produce a business prioritisation rather
    than a port list. The provenance is recorded so the UI can distinguish it
    from anything Veyl measured.
    """
    assets = session.query(Asset).filter(Asset.organization_id == organization_id).all()
    for asset in assets:
        asset.business_criticality = BusinessCriticality.CRITICAL
        asset.data_classification = DataClassification.CONFIDENTIAL
        asset.business_function = BusinessFunction.PAYMENTS
        asset.environment = Environment.PRODUCTION
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
                    source="smoke test owner input",
                    notes="AcmePay classifies this asset as payment-critical.",
                )
            )
    session.commit()

    # Re-score every active finding now that context exists.
    rescore_findings(session, organization_id=organization_id)
    session.commit()


if __name__ == "__main__":
    raise SystemExit(main())
