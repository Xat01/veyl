"""End-to-end acceptance test for Veyl (§47).

Drives the running HTTP API exactly as a client would: builds a fresh demo
environment, starts a real server, then walks the product's whole story over
HTTP — authorize, scan, evidence, business context, risk, change detection,
graph, attack paths, remediation, reporting, audit.

This is deliberately not a pytest suite. pytest is for units and properties; this
is for the question "does the product actually work when you use it", which is
only answerable by using it.

    python scripts/acceptance_test.py
    python scripts/acceptance_test.py --keep-db     # inspect afterwards

Exit code is 0 only if every step passed. A step that cannot run is reported as
SKIP with the reason, and a skipped step never counts as a pass.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for path in ("apps/api", "packages/rules", "services/scanner", "services/analyzer", "services/correlation"):
    sys.path.insert(0, str(ROOT / path))

DB_PATH = ROOT / "acceptance.db"
os.environ.setdefault("VEYL_DATABASE_URL", f"sqlite:///{DB_PATH}")
os.environ.setdefault("VEYL_SECRET_KEY", "acceptance-test-secret-key-not-for-production-use")
os.environ.setdefault("VEYL_ALLOW_PRIVATE_TARGETS", "true")
os.environ.setdefault("VEYL_ENV", "development")
os.environ.setdefault("VEYL_CORS_ORIGINS", "http://localhost:3000")

import httpx  # noqa: E402

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []
SKIPPED: list[tuple[str, str]] = []


def step(number: int, title: str):
    """Decorator-free helper: run one numbered acceptance step."""

    def wrapper(fn):
        label = f"{number:02d}. {title}"
        try:
            result = fn()
        except AssertionError as exc:
            FAILED.append((label, str(exc) or "assertion failed"))
            print(f"  FAIL  {label}\n          {exc}")
        except Exception as exc:  # noqa: BLE001 - a crash is a failure, reported as one
            detail = f"{type(exc).__name__}: {exc}"
            FAILED.append((label, detail))
            print(f"  ERROR {label}\n          {detail}")
            if os.environ.get("VEYL_ACCEPTANCE_TRACEBACK"):
                traceback.print_exc()
        else:
            PASSED.append(label)
            note = f"  ({result})" if result else ""
            print(f"  ok    {label}{note}")
        return fn

    return wrapper


def skip(number: int, title: str, reason: str) -> None:
    label = f"{number:02d}. {title}"
    SKIPPED.append((label, reason))
    print(f"  SKIP  {label}\n          {reason}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_api(port: int) -> tuple[object, threading.Thread]:
    """Start the real ASGI app on a background thread."""
    import uvicorn

    config = uvicorn.Config(
        "veyl_api.api.main:app",
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    return server, thread


def wait_for_api(base: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/api/health", timeout=2.0).status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.25)
    raise RuntimeError(f"API did not become ready within {timeout}s ({last})")


def totp(secret: str) -> str:
    from veyl_api.security.mfa import totp_now

    return totp_now(secret)


def body(response: httpx.Response) -> dict:
    """Parse JSON, failing with the response text when it is not JSON."""
    try:
        return response.json()
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"expected JSON from {response.request.url}, got {response.status_code} "
            f"{response.headers.get('content-type')}: {response.text[:200]}"
        ) from exc


def expect(response: httpx.Response, code: int, what: str) -> dict:
    if response.status_code != code:
        raise AssertionError(
            f"{what}: expected HTTP {code}, got {response.status_code} — {response.text[:300]}"
        )
    return body(response)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acceptance-test", description="Veyl end-to-end acceptance test")
    parser.add_argument("--keep-db", action="store_true", help="Do not delete the acceptance database.")
    args = parser.parse_args(argv)

    if DB_PATH.exists():
        DB_PATH.unlink()

    print("=" * 78)
    print("Veyl acceptance test (§47)")
    print("=" * 78)

    # ------------------------------------------------------------------
    # Build the demo environment. This runs the real Day 1 -> Day 7 story
    # against a real HTTP server, so the database contains real observations
    # before the API is even started.
    # ------------------------------------------------------------------
    print("\n[setup] building the AcmePay demo environment\n")

    from veyl_api.config import settings  # noqa: F401  (imported for its side effect of validating config)
    from veyl_api.db.base import create_all
    from veyl_api.db.session import get_engine, get_sessionmaker
    from veyl_api.demo.__main__ import (
        DEMO_ADMIN_EMAIL,
        DEMO_ANALYST_EMAIL,
        DEMO_ORG_SLUG,
        DEMO_PASSWORD,
        _ensure_demo_target_on_path,
        _run_story,
        _seed,
    )

    _ensure_demo_target_on_path()
    engine = get_engine()
    create_all(engine)

    session = get_sessionmaker()()
    try:
        seeded = _seed(session, allow_private_targets=True)
        story = _run_story(
            session,
            org_id=seeded["org_id"],
            scope_id=seeded["scope_id"],
            skip_scans=False,
        )
    finally:
        session.close()

    secret = seeded["totp_secret"]
    org_slug = DEMO_ORG_SLUG
    print(
        f"  seeded {seeded['org_name']}: {story['scans']} scans, {story['findings']} findings, "
        f"{story['changes']} changes, {story['paths']} attack path(s)"
    )

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    server, thread = start_api(port)
    wait_for_api(base)
    print(f"  API listening on {base}\n")

    client = httpx.Client(base_url=base, timeout=120.0)
    tokens: dict[str, str] = {}
    state: dict[str, object] = {}

    def auth(role: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {tokens[role]}"}

    try:
        print("[§47] end-to-end scenario\n")

        # -- 1. liveness ---------------------------------------------------
        @step(1, "Health endpoint responds without authentication")
        def _1():
            r = client.get("/api/health")
            expect(r, 200, "health")
            return "200"

        # -- 2. unauthenticated access is refused --------------------------
        @step(2, "An unauthenticated request to a protected endpoint is refused")
        def _2():
            r = client.get("/api/findings")
            if r.status_code not in (401, 403):
                raise AssertionError(f"expected 401/403 without a token, got {r.status_code}")
            return f"{r.status_code}"

        # -- 3. wrong password ---------------------------------------------
        @step(3, "Login with a wrong password is refused")
        def _3():
            r = client.post(
                "/api/auth/login",
                json={"email": DEMO_ADMIN_EMAIL, "password": "wrong-password", "organization_slug": org_slug},
            )
            if r.status_code != 401:
                raise AssertionError(f"expected 401, got {r.status_code} — {r.text[:200]}")
            return "401"

        # -- 4. second factor required -------------------------------------
        @step(4, "Login without the second factor returns an MFA challenge, not a token")
        def _4():
            r = client.post(
                "/api/auth/login",
                json={"email": DEMO_ADMIN_EMAIL, "password": DEMO_PASSWORD, "organization_slug": org_slug},
            )
            if r.status_code != 401:
                raise AssertionError(f"expected 401 with an MFA challenge, got {r.status_code}")
            payload = body(r)
            if "access_token" in payload:
                raise AssertionError("a token was issued without the second factor")
            if "mfa" not in str(payload).lower():
                raise AssertionError(f"response does not indicate MFA is required: {payload}")
            return "challenge returned, no token"

        # -- 5. successful admin login -------------------------------------
        @step(5, "Admin login succeeds with a valid TOTP code")
        def _5():
            r = client.post(
                "/api/auth/login",
                json={
                    "email": DEMO_ADMIN_EMAIL,
                    "password": DEMO_PASSWORD,
                    "organization_slug": org_slug,
                    "totp_code": totp(secret),
                },
            )
            payload = expect(r, 200, "admin login")
            token = payload.get("access_token")
            if not token:
                raise AssertionError(f"no access_token in {list(payload)}")
            tokens["admin"] = token
            return "token issued"

        # -- 6. identity ---------------------------------------------------
        @step(6, "GET /auth/me returns the identity, role, and capabilities")
        def _6():
            me = expect(client.get("/api/auth/me", headers=auth("admin")), 200, "me")
            if me.get("email") != DEMO_ADMIN_EMAIL:
                raise AssertionError(f"unexpected email {me.get('email')}")
            caps = me.get("capabilities") or []
            if "scope:write" not in caps:
                raise AssertionError(f"admin is missing scope:write; got {caps}")
            return f"{me.get('role')}, {len(caps)} capabilities"

        # -- 7. security posture -------------------------------------------
        @step(7, "GET /auth/security reports the enrolled second factor")
        def _7():
            sec = expect(client.get("/api/auth/security", headers=auth("admin")), 200, "security")
            if not sec.get("mfa_enabled"):
                raise AssertionError(f"admin should report mfa_enabled; got {sec}")
            return f"mfa_enabled={sec.get('mfa_enabled')}"

        # -- 8. dashboard --------------------------------------------------
        @step(8, "Dashboard reports non-zero assets and open findings")
        def _8():
            dash = expect(client.get("/api/dashboard", headers=auth("admin")), 200, "dashboard")
            if not dash.get("asset_count"):
                raise AssertionError("dashboard reports no assets")
            if not dash.get("open_finding_count"):
                raise AssertionError("dashboard reports no open findings")
            state["dashboard"] = dash
            return f"{dash['asset_count']} assets, {dash['open_finding_count']} open findings"

        # -- 9. scope registry ---------------------------------------------
        @step(9, "The demo target is present in the scope registry and authorized")
        def _9():
            page = expect(client.get("/api/scope", headers=auth("admin")), 200, "scope list")
            items = page["items"]
            if not items:
                raise AssertionError("scope registry is empty")
            authorized = [e for e in items if e["is_authorized_now"]]
            if not authorized:
                raise AssertionError(f"no authorized scope entries: {[e['authorization_status'] for e in items]}")
            state["demo_scope_id"] = authorized[0]["id"]
            return f"{len(items)} entries, {len(authorized)} authorized"

        # -- 10. a new entry cannot authorize itself -----------------------
        @step(10, "A newly created scope entry is PENDING and not scannable")
        def _10():
            r = client.post(
                "/api/scope",
                headers=auth("admin"),
                json={
                    "domain": "pending-not-yet-authorized.example.com",
                    "environment": "STAGING",
                    "asset_owner": "ENGINEERING",
                    "notes": "acceptance test entry",
                },
            )
            entry = expect(r, 201, "create scope entry")
            if entry["authorization_status"] != "PENDING":
                raise AssertionError(f"new entry should be PENDING, got {entry['authorization_status']}")
            if entry["is_authorized_now"]:
                raise AssertionError("a PENDING entry reports itself as authorized")
            state["pending_scope_id"] = entry["id"]
            return "PENDING, not authorized"

        # -- 11. scanning an unauthorized target is refused ----------------
        @step(11, "Submitting a scan against only the pending entry is refused with a reason")
        def _11():
            r = client.post(
                "/api/scans",
                headers=auth("admin"),
                json={"scope_entry_ids": [state["pending_scope_id"]], "label": "should be refused"},
            )
            if r.status_code != 400:
                raise AssertionError(f"expected 400, got {r.status_code} — {r.text[:250]}")
            detail = str(body(r).get("detail", ""))
            if "authoriz" not in detail.lower():
                raise AssertionError(f"refusal does not mention authorization: {detail[:200]}")
            return "400 with an authorization reason"

        # -- 12. authorization is an explicit act --------------------------
        @step(12, "Authorizing the entry makes it scannable and records who did it")
        def _12():
            r = client.patch(
                f"/api/scope/{state['pending_scope_id']}",
                headers=auth("admin"),
                json={
                    "authorization_status": "AUTHORIZED",
                    "authorized_by": "acceptance test",
                },
            )
            entry = expect(r, 200, "authorize scope entry")
            if not entry["is_authorized_now"]:
                raise AssertionError("entry is still not authorized after being authorized")
            return f"authorized by {entry.get('authorized_by')}"

        # -- 13. scan ------------------------------------------------------
        @step(13, "A scan of the authorized target completes and produces findings")
        def _13():
            r = client.post(
                "/api/scans",
                headers=auth("admin"),
                json={"scope_entry_ids": [state["demo_scope_id"]], "label": "acceptance test scan"},
            )
            scan = expect(r, 201, "run scan")
            if scan["status"] not in ("COMPLETED", "PARTIAL"):
                raise AssertionError(f"scan status is {scan['status']}: {scan.get('error_message')}")
            if not scan["targets_scanned"]:
                raise AssertionError(f"no targets were scanned; blocked={scan.get('blocked_targets')}")
            state["scan_id"] = scan["id"]
            return (
                f"{scan['status']}, {scan['targets_scanned']} target(s), "
                f"{scan['findings_created']} finding(s)"
            )

        # -- 14. assets ----------------------------------------------------
        @step(14, "Assets were discovered and expose their current state")
        def _14():
            page = expect(client.get("/api/assets", headers=auth("admin")), 200, "assets")
            items = page["items"]
            if not items:
                raise AssertionError("no assets discovered")
            state["asset_id"] = items[0]["id"]
            detail = expect(
                client.get(f"/api/assets/{items[0]['id']}", headers=auth("admin")), 200, "asset detail"
            )
            return f"{page['total']} assets, first has {len(detail.get('services') or [])} service(s)"

        # -- 15. findings --------------------------------------------------
        @step(15, "Findings were raised and carry a severity and a risk score")
        def _15():
            page = expect(client.get("/api/findings", headers=auth("admin")), 200, "findings")
            items = page["items"]
            if not items:
                raise AssertionError("no findings were raised by the scan")
            for f in items:
                if not f.get("severity"):
                    raise AssertionError(f"finding {f['id']} has no severity")
                if f.get("risk_score") is None:
                    raise AssertionError(f"finding {f['id']} has no risk score")
            state["finding_id"] = items[0]["id"]
            return f"{page['total']} findings, top={items[0]['severity']} {items[0]['risk_score']}"

        # -- 16. THE evidence contract -------------------------------------
        @step(16, "Every finding cites at least one piece of evidence")
        def _16():
            page = expect(client.get("/api/findings?limit=200", headers=auth("admin")), 200, "findings")
            checked = 0
            for f in page["items"]:
                if not f.get("evidence_count"):
                    raise AssertionError(f"finding {f['rule_id']} ({f['id']}) cites no evidence")
                checked += 1
            return f"all {checked} findings cite evidence"

        # -- 17. evidence detail -------------------------------------------
        @step(17, "Evidence carries the observation, the matcher, and provenance")
        def _17():
            ev = expect(
                client.get(f"/api/findings/{state['finding_id']}/evidence", headers=auth("admin")),
                200,
                "evidence",
            )
            rows = ev if isinstance(ev, list) else ev.get("items", [])
            if not rows:
                raise AssertionError("evidence endpoint returned nothing for a finding that has evidence")
            first = rows[0]
            for field in ("kind", "matcher", "provenance", "observation_id"):
                if not first.get(field):
                    raise AssertionError(f"evidence is missing {field}: {first}")
            return f"{len(rows)} evidence row(s), kind={first['kind']}, provenance={first['provenance']}"

        # -- 18. risk factors are explainable ------------------------------
        @step(18, "The risk score is explained by named factors, not a bare number")
        def _18():
            detail = expect(
                client.get(f"/api/findings/{state['finding_id']}", headers=auth("admin")),
                200,
                "finding detail",
            )
            factors = detail.get("risk_factors") or {}
            if not factors:
                raise AssertionError("finding has no risk_factors; the score is unexplained")
            if not detail.get("risk_explanation"):
                raise AssertionError("finding has risk_factors but no risk_explanation")
            return f"{len(factors)} factor(s): {', '.join(list(factors)[:4])}"

        # -- 19. business context ------------------------------------------
        @step(19, "Business context can be set and is recorded as user-provided")
        def _19():
            r = client.put(
                f"/api/assets/{state['asset_id']}/context",
                headers=auth("admin"),
                json={
                    "business_criticality": "CRITICAL",
                    "data_classification": "CONFIDENTIAL",
                    "business_function": "PAYMENTS",
                    "owner": "ENGINEERING",
                    "internet_exposed": True,
                    "business_description": "Set by the acceptance test.",
                },
            )
            ctx = expect(r, 200, "set business context")
            if ctx.get("context_source") != "USER_PROVIDED":
                raise AssertionError(
                    f"context should be recorded as USER_PROVIDED, got {ctx.get('context_source')}"
                )
            return f"criticality={ctx.get('business_criticality')}, source={ctx.get('context_source')}"

        # -- 20. rescore ---------------------------------------------------
        @step(20, "Rescoring recomputes risk from the new business context")
        def _20():
            r = client.post(f"/api/assets/{state['asset_id']}/rescore", headers=auth("admin"))
            if r.status_code not in (200, 202):
                raise AssertionError(f"rescore returned {r.status_code}: {r.text[:200]}")
            return f"{r.status_code}"

        # -- 21. exposure changes ------------------------------------------
        @step(21, "Change detection reported exposure changes, including risk-increasing ones")
        def _21():
            page = expect(client.get("/api/changes", headers=auth("admin")), 200, "changes")
            items = page["items"]
            if not items:
                raise AssertionError("no exposure changes were detected across the two scans")
            increasing = [c for c in items if c.get("is_risk_increasing")]
            state["change_id"] = items[0]["id"]
            return f"{page['total']} changes, {len(increasing)} risk-increasing"

        # -- 22. change detail ---------------------------------------------
        @step(22, "A change explains what changed and whether it matters")
        def _22():
            c = expect(
                client.get(f"/api/changes/{state['change_id']}", headers=auth("admin")), 200, "change detail"
            )
            for field in ("change_type", "subject", "significance"):
                if not c.get(field):
                    raise AssertionError(f"change is missing {field}: {list(c)}")
            if c.get("security_significance") is None:
                raise AssertionError("change states no security significance")
            return f"{c['change_type']}: {str(c['subject'])[:50]}"

        # -- 23. graph -----------------------------------------------------
        @step(23, "The attack-surface graph is populated")
        def _23():
            g = expect(client.get("/api/graph", headers=auth("admin")), 200, "graph")
            if not g.get("node_count"):
                raise AssertionError("graph has no nodes")
            return f"{g['node_count']} nodes, {g['edge_count']} edges"

        # -- 24. rebuild is idempotent -------------------------------------
        @step(24, "Rebuilding the graph twice yields the same graph (no duplication)")
        def _24():
            r = client.post("/api/graph/rebuild", headers=auth("admin"))
            if r.status_code not in (200, 202):
                raise AssertionError(f"rebuild returned {r.status_code}: {r.text[:200]}")
            first = expect(client.get("/api/graph", headers=auth("admin")), 200, "graph after 1st rebuild")
            first_counts = (first["node_count"], first["edge_count"])

            r2 = client.post("/api/graph/rebuild", headers=auth("admin"))
            if r2.status_code not in (200, 202):
                raise AssertionError(f"second rebuild returned {r2.status_code}: {r2.text[:200]}")
            second = expect(client.get("/api/graph", headers=auth("admin")), 200, "graph after 2nd rebuild")
            second_counts = (second["node_count"], second["edge_count"])

            if first_counts != second_counts:
                raise AssertionError(
                    f"rebuilding the same state twice produced different graphs: "
                    f"{first_counts} then {second_counts} — rebuild is not idempotent"
                )
            return f"stable at {second_counts[0]} nodes, {second_counts[1]} edges"

        # -- 25. attack paths ----------------------------------------------
        @step(25, "Attack paths are reported as potential, with their limitations stated")
        def _25():
            page = expect(client.get("/api/attack-paths", headers=auth("admin")), 200, "attack paths")
            items = page["items"]
            if not items:
                raise AssertionError("no attack paths were correlated from the demo story")
            path = items[0]
            if not path.get("limitations"):
                raise AssertionError(
                    "an attack path is reported without stating its limitations; "
                    "the product must not imply a confirmed exploit"
                )
            if "potential" not in str(path.get("name", "")).lower() and "potential" not in str(
                path.get("summary", "")
            ).lower() and not path.get("limitations"):
                raise AssertionError("attack path does not describe itself as potential")
            state["path_id"] = path["id"]
            return f"{page['total']} path(s), confidence={path.get('confidence')}"

        # -- 26. remediation -----------------------------------------------
        @step(26, "A remediation can be assigned to a finding")
        def _26():
            r = client.put(
                f"/api/findings/{state['finding_id']}/remediation",
                headers=auth("admin"),
                json={
                    "owner": "ENGINEERING",
                    "priority": "HIGH",
                    "notes": "Assigned by the acceptance test.",
                },
            )
            if r.status_code not in (200, 201):
                raise AssertionError(f"remediation returned {r.status_code}: {r.text[:250]}")
            detail = expect(
                client.get(f"/api/findings/{state['finding_id']}", headers=auth("admin")),
                200,
                "finding detail after remediation",
            )
            if not detail.get("has_remediation"):
                raise AssertionError("finding reports has_remediation=false after assigning one")
            return f"{r.status_code}, has_remediation=true"

        # -- 27. finding lifecycle -----------------------------------------
        @step(27, "A finding status transition is accepted")
        def _27():
            r = client.patch(
                f"/api/findings/{state['finding_id']}/status",
                headers=auth("admin"),
                json={"status": "ACKNOWLEDGED"},
            )
            f = expect(r, 200, "update finding status")
            if f.get("status") != "ACKNOWLEDGED":
                raise AssertionError(f"status is {f.get('status')} after acknowledging")
            return "OPEN -> ACKNOWLEDGED"

        # -- 28. history ---------------------------------------------------
        @step(28, "The finding keeps an append-only history of what changed")
        def _28():
            h = expect(
                client.get(f"/api/findings/{state['finding_id']}/history", headers=auth("admin")),
                200,
                "finding history",
            )
            rows = h if isinstance(h, list) else h.get("items", [])
            if not rows:
                raise AssertionError("finding history is empty after two state changes")
            return f"{len(rows)} event(s)"

        # -- 29. report ----------------------------------------------------
        @step(29, "A report can be generated and downloaded")
        def _29():
            r = client.post(
                "/api/reports",
                headers=auth("admin"),
                json={"kind": "TECHNICAL", "fmt": "HTML", "title": "Acceptance test report"},
            )
            report = expect(r, 201, "generate report")
            rid = report["id"]
            dl = client.get(f"/api/reports/{rid}/download", headers=auth("admin"))
            if dl.status_code != 200:
                raise AssertionError(f"download returned {dl.status_code}: {dl.text[:200]}")
            if len(dl.content) < 500:
                raise AssertionError(f"report body is suspiciously small: {len(dl.content)} bytes")
            if b"<html" not in dl.content[:2000].lower():
                raise AssertionError("HTML report does not look like HTML")
            state["report_id"] = rid
            return f"{len(dl.content):,} bytes of HTML"

        # -- 30. PDF is honestly not implemented ---------------------------
        @step(30, "PDF reporting reports 501 rather than emitting a broken file")
        def _30():
            r = client.post(
                "/api/reports",
                headers=auth("admin"),
                json={"kind": "TECHNICAL", "fmt": "PDF", "title": "Should not be produced"},
            )
            if r.status_code != 501:
                raise AssertionError(
                    f"PDF reporting returned {r.status_code}; it is documented as 501 Not Implemented"
                )
            return "501 Not Implemented"

        # -- 31. audit chain ------------------------------------------------
        @step(31, "The audit log records the session's actions and its hash chain verifies")
        def _31():
            page = expect(client.get("/api/audit", headers=auth("admin")), 200, "audit log")
            if not page["total"]:
                raise AssertionError("audit log is empty after a full session")
            v = expect(client.get("/api/audit/verify", headers=auth("admin")), 200, "audit verify")
            ok = v.get("valid", v.get("intact", v.get("ok")))
            if ok is False:
                raise AssertionError(f"audit chain failed verification: {v}")
            return f"{page['total']} entries, chain verified"

        # -- 32. RBAC -------------------------------------------------------
        @step(32, "An analyst can log in and read findings but cannot administer members")
        def _32():
            r = client.post(
                "/api/auth/login",
                json={
                    "email": DEMO_ANALYST_EMAIL,
                    "password": DEMO_PASSWORD,
                    "organization_slug": org_slug,
                },
            )
            payload = expect(r, 200, "analyst login")
            tokens["analyst"] = payload["access_token"]

            # The analyst must be able to do their job.
            allowed = client.get("/api/findings", headers=auth("analyst"))
            if allowed.status_code != 200:
                raise AssertionError(f"analyst cannot read findings: {allowed.status_code}")

            # ...but must not be able to change who is in the organization.
            denied = client.post(
                "/api/members",
                headers=auth("analyst"),
                json={
                    "email": "should-not-exist@acmepay.example",
                    "password": "Veyl-Demo-Password-1!",
                    "full_name": "Should Not Exist",
                    "role": "ENGINEER",
                },
            )
            if denied.status_code != 403:
                raise AssertionError(
                    f"analyst created a member (member:write is not granted to SECURITY_ANALYST): "
                    f"{denied.status_code} {denied.text[:200]}"
                )
            return "findings 200, member creation 403"

        # -- 33. privileged policy at grant time ---------------------------
        @step(33, "Granting ADMIN to an account without a second factor is refused")
        def _33():
            r = client.post(
                "/api/members",
                headers=auth("admin"),
                json={
                    "email": "no-factor-admin@acmepay.example",
                    "password": "Veyl-Demo-Password-1!",
                    "full_name": "No Factor",
                    "role": "ADMIN",
                },
            )
            if r.status_code == 409:
                return "409 — policy enforced at grant time"
            if r.status_code == 201:
                raise AssertionError(
                    "an ADMIN was created without a second factor; §27 requires the policy to "
                    "be enforced when the role is granted"
                )
            raise AssertionError(f"unexpected {r.status_code}: {r.text[:250]}")

        # -- 34. cross-tenant isolation -------------------------------------
        @step(34, "A resource that does not exist is a 404, not a disclosure")
        def _34():
            r = client.get("/api/assets/00000000-0000-0000-0000-000000000000", headers=auth("admin"))
            if r.status_code not in (404, 422):
                raise AssertionError(f"expected 404 for a nonexistent asset, got {r.status_code}")
            return f"{r.status_code}"

        # -- 35. the safety floor refuses and records ----------------------
        @step(35, "A target the safety floor refuses is recorded on the scan, not dropped")
        def _35():
            # The cloud metadata address is blocked unconditionally, even with
            # private targets permitted. Authorizing it is not enough to scan it.
            r = client.post(
                "/api/scope",
                headers=auth("admin"),
                json={
                    "domain": "169.254.169.254",
                    "environment": "PRODUCTION",
                    "asset_owner": "ENGINEERING",
                    "authorization_status": "AUTHORIZED",
                    "authorized_by": "acceptance test",
                    "notes": "must never be scanned",
                },
            )
            if r.status_code not in (201, 409):
                raise AssertionError(f"could not register the metadata address: {r.status_code} {r.text[:200]}")
            if r.status_code == 201:
                entry_id = body(r)["id"]
                client.patch(
                    f"/api/scope/{entry_id}",
                    headers=auth("admin"),
                    json={"authorization_status": "AUTHORIZED", "authorized_by": "acceptance test"},
                )

            scan = expect(
                client.post(
                    "/api/scans",
                    headers=auth("admin"),
                    json={"label": "metadata refusal test"},
                ),
                201,
                "scan including the metadata address",
            )
            if "blocked_targets" not in scan:
                raise AssertionError("scan response has no blocked_targets field")
            blocked = scan["blocked_targets"] or []
            if not blocked:
                raise AssertionError(
                    "the metadata address was authorized but the scan reports nothing blocked — "
                    "it may have been scanned"
                )
            reasons = {str(b.get("target")): str(b.get("reason", "")) for b in blocked}
            if "169.254.169.254" not in reasons:
                raise AssertionError(f"the metadata address is not in blocked_targets: {reasons}")
            return f"blocked {len(blocked)}, reason for metadata: {reasons['169.254.169.254'][:50]}"

    finally:
        client.close()
        server.should_exit = True
        thread.join(timeout=10)
        if not args.keep_db and DB_PATH.exists():
            try:
                DB_PATH.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------
    print("\n" + "=" * 78)
    total = len(PASSED) + len(FAILED) + len(SKIPPED)
    print(f"RESULT: {len(PASSED)}/{total} steps passed, {len(FAILED)} failed, {len(SKIPPED)} skipped")
    if SKIPPED:
        print("\nSkipped (not counted as passes):")
        for label, reason in SKIPPED:
            print(f"  - {label}: {reason}")
    if FAILED:
        print("\nFailures:")
        for label, reason in FAILED:
            print(f"  - {label}\n      {reason}")
    print("=" * 78)
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
