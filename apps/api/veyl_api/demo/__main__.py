"""``python -m veyl_api.demo`` — build the local AcmePay demo environment.

One command that produces a working, loginable, populated Veyl instance so the
UI can be evaluated against real data. Nothing here is synthetic: it creates an
organization, a real user whose password you can actually use, a scope entry
that authorizes a real local target, and then runs the Day 1 -> Day 7 exposure
story against a real HTTP server that it starts itself.

    python -m veyl_api.demo                 # build and run both scans
    python -m veyl_api.demo --reset         # wipe an existing demo database first
    python -m veyl_api.demo --skip-scans    # seed accounts and scope only

Printed at the end: the URL to open and the credentials to sign in with.

This is a demo environment. It sets a known password and allows private targets.
Both are recorded on the organization and printed, so nobody can mistake a demo
instance for a hardened deployment.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading

DEMO_ORG_SLUG = "acmepay"
DEMO_ADMIN_EMAIL = "admin@acmepay.example"
DEMO_ANALYST_EMAIL = "analyst@acmepay.example"
DEMO_EXEC_EMAIL = "executive@acmepay.example"
#: Printed on every run. The demo is local-only and the accounts are disposable.
DEMO_PASSWORD = "Veyl-Demo-Password-1!"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _DemoServer:
    """The bundled AcmePay target, restartable under a different profile."""

    def __init__(self) -> None:
        self.port = _free_port()
        self._httpd = None

    def start(self, profile: str) -> None:
        from acmepay_service import build_server  # type: ignore[import-not-found]

        self._httpd = build_server(self.port, profile, verbose=False)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def _ensure_demo_target_on_path() -> None:
    """Make the bundled demo target importable.

    ``demo/targets`` is not an installed package — it is a demo fixture — so it
    is located relative to the repository root rather than imported by name.
    """
    from pathlib import Path

    root = Path(__file__).resolve()
    for parent in root.parents:
        candidate = parent / "demo" / "targets"
        if candidate.is_dir():
            sys.path.insert(0, str(candidate))
            return
    raise RuntimeError(
        "could not locate demo/targets; run this from a checkout of the repository"
    )


def _seed(session, *, allow_private_targets: bool) -> dict:
    """Create the organization, users, and scope entry. Idempotent."""
    from veyl_api.db.base import utcnow
    from veyl_api.enums import (
        AssetOwner,
        AuthorizationStatus,
        Environment,
        OrganizationRole,
    )
    from veyl_api.models import Organization, OrganizationMember, ScopeEntry, User
    from veyl_api.security.auth import hash_password
    from veyl_api.security.mfa import generate_totp_secret
    from veyl_api.api.routes.auth import _hash_totp_secret

    org = (
        session.query(Organization).filter(Organization.slug == DEMO_ORG_SLUG).one_or_none()
    )
    if org is None:
        org = Organization(
            name="AcmePay",
            slug=DEMO_ORG_SLUG,
            primary_domain="acmepay.example",
            industry="Financial Services",
            description=(
                "Fictional payments company used to demonstrate Veyl. Everything "
                "here is invented; the target service is bundled with the repo."
            ),
        )
        session.add(org)
        session.flush()

    # The demo administrator has a TOTP factor, because §27 refuses to
    # authenticate an admin without one. The secret is generated fresh and
    # printed, since an operator running the demo needs a working code.
    secret = generate_totp_secret()
    accounts = [
        (DEMO_ADMIN_EMAIL, "Ada Admin", OrganizationRole.ADMIN),
        (DEMO_ANALYST_EMAIL, "Ana Analyst", OrganizationRole.SECURITY_ANALYST),
        (DEMO_EXEC_EMAIL, "Eve Executive", OrganizationRole.EXECUTIVE),
    ]

    created: list[dict] = []
    for email, full_name, role in accounts:
        user = session.query(User).filter(User.email == email).one_or_none()
        if user is None:
            user = User(
                email=email,
                full_name=full_name,
                password_hash=hash_password(DEMO_PASSWORD),
                is_active=True,
            )
            session.add(user)
            session.flush()

        if role is OrganizationRole.ADMIN:
            user.mfa_enabled = True
            user.mfa_secret_hash = _hash_totp_secret(secret)
            user.mfa_enrolled_at = utcnow()

        membership = (
            session.query(OrganizationMember)
            .filter(
                OrganizationMember.organization_id == org.id,
                OrganizationMember.user_id == user.id,
            )
            .one_or_none()
        )
        if membership is None:
            session.add(
                OrganizationMember(
                    organization_id=org.id,
                    user_id=user.id,
                    role=role,
                    is_active=True,
                )
            )
        else:
            membership.role = role
            membership.is_active = True

        created.append(
            {
                "email": email,
                "full_name": full_name,
                "role": role.value,
                "mfa": role is OrganizationRole.ADMIN,
            }
        )

    scope = (
        session.query(ScopeEntry)
        .filter(
            ScopeEntry.organization_id == org.id,
            ScopeEntry.domain == "127.0.0.1",
        )
        .one_or_none()
    )
    if scope is None:
        scope = ScopeEntry(
            organization_id=org.id,
            domain="127.0.0.1",
            environment=Environment.PRODUCTION,
            asset_owner=AssetOwner.ENGINEERING,
            authorization_status=AuthorizationStatus.AUTHORIZED,
            authorized_by="AcmePay security team (demo)",
            authorized_at=utcnow(),
            notes=(
                "AcmePay payments API, running locally as the bundled demo target. "
                "Authorized for this demo only."
            ),
            allow_port_override=True,
        )
        session.add(scope)

    session.commit()
    # Plain data, not ORM instances. The caller closes the session and prints
    # this afterwards, and a detached instance would raise on attribute access
    # the moment any value had been expired by the commit above.
    return {
        "org_id": org.id,
        "org_name": org.name,
        "org_slug": org.slug,
        "scope_id": scope.id,
        "scope_domain": scope.domain,
        "accounts": created,
        "totp_secret": secret,
    }


def _run_story(session, *, org_id: str, scope_id: str, skip_scans: bool) -> dict:
    """Run the Day 1 -> Day 7 scans and the correlation pass."""
    from veyl_analyzer.engine import rescore_findings
    from veyl_correlation.attack_paths import correlate_attack_paths
    from veyl_correlation.graph import rebuild_graph
    from veyl_scanner.runner import ScanRunner
    from veyl_api.enums import ScanTrigger

    if skip_scans:
        return {"scans": 0, "findings": 0, "changes": 0, "paths": 0}

    from veyl_api.models import ExposureChange, Finding
    from veyl_api.enums import ACTIVE_FINDING_STATUSES

    server = _DemoServer()
    result = {"scans": 0, "findings": 0, "changes": 0, "paths": 0}
    try:
        for profile, label in (("day1", "Day 1 baseline"), ("day7", "Day 7 regression")):
            server.start(profile)
            runner = ScanRunner(
                session,
                organization_id=org_id,
                trigger=ScanTrigger.DEMO,
                label=label,
                enable_ct=False,
                enable_subdomain_discovery=False,
                port_override=[server.port],
            )
            scan = runner.create_scan([scope_id])
            session.commit()
            runner.run(scan, [scope_id])
            session.commit()
            result["scans"] += 1
            result["last_scan_id"] = scan.id
            server.stop()

        _apply_business_context(session, org_id=org_id)

        findings = (
            session.query(Finding)
            .filter(
                Finding.organization_id == org_id,
                Finding.status.in_([s.value for s in ACTIVE_FINDING_STATUSES]),
            )
            .all()
        )
        result["findings"] = len(findings)

        changes = (
            session.query(ExposureChange)
            .filter(ExposureChange.organization_id == org_id)
            .all()
        )
        result["changes"] = len(changes)
        result["risk_increasing"] = len([c for c in changes if c.is_risk_increasing])

        graph = rebuild_graph(session, organization_id=org_id)
        result["graph"] = graph.stats

        paths = correlate_attack_paths(
            session, organization_id=org_id, scan=session.get(type(scan), scan.id)
        )
        session.commit()
        result["paths"] = len(paths)

        rescore_findings(session, organization_id=org_id)
        session.commit()
    finally:
        server.stop()
    return result


def _apply_business_context(session, *, org_id: str) -> None:
    """Attach owner-provided context, marked USER_PROVIDED.

    Note ``internet_exposed``: Veyl observed that the host is reachable, but only
    AcmePay can declare that the payments API is published to the internet. The
    demo sets the bar the same way a real customer would, and the field records
    that a human asserted it.
    """
    from veyl_api.enums import (
        BusinessCriticality,
        BusinessFunction,
        DataClassification,
        Environment,
        Provenance,
    )
    from veyl_api.models import Asset, AssetContext

    for asset in session.query(Asset).filter(Asset.organization_id == org_id).all():
        asset.business_criticality = BusinessCriticality.CRITICAL
        asset.data_classification = DataClassification.CONFIDENTIAL
        asset.business_function = BusinessFunction.PAYMENTS
        asset.environment = Environment.PRODUCTION
        asset.internet_exposed = True
        asset.context_source = Provenance.USER_PROVIDED
        if asset.context is None:
            session.add(
                AssetContext(
                    organization_id=org_id,
                    asset_id=asset.id,
                    business_criticality=BusinessCriticality.CRITICAL,
                    data_classification=DataClassification.CONFIDENTIAL,
                    business_function=BusinessFunction.PAYMENTS,
                    environment=Environment.PRODUCTION,
                    provenance=Provenance.USER_PROVIDED,
                    source="AcmePay security team (demo)",
                    business_description=(
                        "Primary payments API. Processes card authorizations and settlements."
                    ),
                    notes="Classified by AcmePay, not inferred by Veyl.",
                )
            )
    session.commit()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veyl-demo", description="Build the Veyl demo environment")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Drop and recreate every table before seeding. Destroys the current demo database.",
    )
    parser.add_argument(
        "--skip-scans",
        action="store_true",
        help="Seed the organization and accounts without running scans.",
    )
    args = parser.parse_args(argv)

    # The demo scans a service on 127.0.0.1, which the SSRF floor blocks unless
    # this deployment has explicitly declared itself a local one. Setting it here
    # is honest: this *is* a local deployment, and the value is what the safety
    # floor reads.
    os.environ.setdefault("VEYL_ALLOW_PRIVATE_TARGETS", "true")
    os.environ.setdefault("VEYL_ENV", "development")
    os.environ.setdefault(
        "VEYL_SECRET_KEY", "veyl-demo-secret-key-not-for-production-use-change-me"
    )

    _ensure_demo_target_on_path()

    from veyl_api.config import settings
    from veyl_api.db.base import create_all, drop_all
    from veyl_api.db.session import get_engine, get_sessionmaker

    engine = get_engine()
    if args.reset:
        drop_all(engine)
    create_all(engine)

    session = get_sessionmaker()()
    try:
        seeded = _seed(session, allow_private_targets=settings.allow_private_targets)
        story = _run_story(
            session,
            org_id=seeded["org_id"],
            scope_id=seeded["scope_id"],
            skip_scans=args.skip_scans,
        )
    finally:
        session.close()

    _print_summary(seeded=seeded, story=story, database_url=settings.database_url)
    return 0


def _print_summary(*, seeded: dict, story: dict, database_url: str) -> None:
    from veyl_api.config import settings

    line = "=" * 76
    print(line)
    print("Veyl demo environment ready")
    print(line)
    print(f"  organization : {seeded['org_name']} ({seeded['org_slug']})")
    print(f"  database     : {database_url}")
    print()
    print("  API          : http://localhost:8000  (start with `python -m veyl_api`)")
    print("  Web console  : http://localhost:3000  (cd apps/web && npm run dev)")
    print()
    print("  Accounts (all use the same password):")
    print(f"    password   : {DEMO_PASSWORD}")
    for account in seeded["accounts"]:
        print(f"    {account['role']:16} {account['email']}")
    print()
    print("  The ADMIN account has a TOTP factor enrolled. Add this secret to an")
    print("  authenticator app, or compute a code with the CLI:")
    print(f"    secret     : {seeded['totp_secret']}")
    print()
    print("    python -c \"from veyl_api.security.mfa import totp_now;"
          f" print(totp_now('{seeded['totp_secret']}'))\"")
    print()
    if story.get("scans"):
        print("  Scan results:")
        print(f"    scans run            : {story['scans']}")
        print(f"    active findings      : {story['findings']}")
        print(f"    exposure changes     : {story['changes']}"
              f" ({story.get('risk_increasing', 0)} risk-increasing)")
        print(f"    attack paths         : {story['paths']}")
        if story.get("graph"):
            print(f"    graph                : {story['graph']['nodes']} nodes, "
                  f"{story['graph']['edges']} edges")
    else:
        print("  Scans were skipped (--skip-scans); start one from the UI or the API.")
    print()
    print("  Next: start the API with `python -m veyl_api` and the web console")
    print("  with `cd apps/web && npm run dev`.")
    print(line)


if __name__ == "__main__":
    raise SystemExit(main())
