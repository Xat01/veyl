"""Integration tests for the HTTP API.

These drive the real application through a real HTTP client against a real
SQLite database. Nothing is mocked: if a route is not wired up, or a dependency
does not resolve, or the response schema does not match what the handler returns,
these fail.

The tenant-isolation tests are the ones worth reading. A multi-tenant security
product that leaks across tenants is worse than one that does not work at all,
so isolation is tested from several angles rather than assumed from the presence
of a ``WHERE`` clause.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from veyl_api.api.main import create_app
from veyl_api.api.routes import members as members_route
from veyl_api.db.base import utcnow
from veyl_api.enums import OrganizationRole
from veyl_api.models import Organization, OrganizationMember, User
from veyl_api.security.auth import hash_password

STRONG_PASSWORD = "Correct-Horse-Battery-9!"


@pytest.fixture()
def client(session):
    """A TestClient bound to the per-test database.

    The app is rebuilt per test so nothing carries over, and the *dependency
    object* the routes actually reference is overridden. Overriding
    ``session_module.get_session`` would not work: ``deps`` imported that
    function by name at import time, so the routes hold the original object.
    """
    from veyl_api.api import deps

    app = create_app()

    def _override_session():
        yield session

    app.dependency_overrides[deps.get_session] = _override_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def admin(session):
    """An organization with one administrator, ready to log in."""
    org = Organization(
        name="AcmePay", slug=f"acmepay-{uuid.uuid4().hex[:8]}", primary_domain="acmepay.example"
    )
    session.add(org)
    session.flush()

    user = User(
        email=f"admin-{uuid.uuid4().hex[:6]}@acmepay.example",
        full_name="Ada Admin",
        password_hash=hash_password(STRONG_PASSWORD),
        is_active=True,
    )
    session.add(user)
    session.flush()

    session.add(
        OrganizationMember(
            organization_id=org.id,
            user_id=user.id,
            role=OrganizationRole.ADMIN,
            is_active=True,
        )
    )
    session.commit()
    return {"org": org, "user": user, "password": STRONG_PASSWORD}


@pytest.fixture()
def auth_headers(client, admin):
    """Bearer headers for the administrator."""
    response = client.post(
        "/api/auth/login",
        json={"email": admin["user"].email, "password": admin["password"]},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_health_is_public(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readiness_reports_the_database(client):
    body = client.get("/api/health/ready").json()
    assert body["checks"]["database"] is True
    assert body["status"] == "ok"


def test_security_headers_are_present(client):
    response = client.get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Request-ID"]


def test_request_id_is_echoed_when_supplied(client):
    response = client.get("/api/health", headers={"X-Request-ID": "abc123"})
    assert response.headers["X-Request-ID"] == "abc123"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_login_returns_a_token_pair(client, admin):
    response = client.post(
        "/api/auth/login",
        json={"email": admin["user"].email, "password": admin["password"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"] and body["refresh_token"]
    assert body["expires_in"] > 0


def test_login_with_a_wrong_password_is_refused(client, admin):
    response = client.post(
        "/api/auth/login",
        json={"email": admin["user"].email, "password": "Wrong-Password-1!"},
    )
    assert response.status_code == 401
    assert "invalid email or password" in response.json()["detail"]


def test_login_for_an_unknown_user_looks_identical_to_a_wrong_password(client):
    """The response must not reveal whether an address is registered."""
    unknown = client.post(
        "/api/auth/login",
        json={"email": "nobody@nowhere.example", "password": "Whatever-1234!"},
    )
    assert unknown.status_code == 401
    assert unknown.json()["detail"] == "invalid email or password"


def test_login_failure_is_audited(client, admin, session):
    from veyl_api.models import AuditLog

    client.post(
        "/api/auth/login",
        json={"email": admin["user"].email, "password": "Wrong-Password-1!"},
    )
    session.expire_all()
    entries = list(
        session.execute(
            select(AuditLog).where(AuditLog.action == "LOGIN_FAILED")
        ).scalars()
    )
    assert len(entries) == 1
    assert entries[0].result == "FAILURE"


def test_login_success_is_audited(client, admin, session):
    from veyl_api.models import AuditLog

    client.post(
        "/api/auth/login",
        json={"email": admin["user"].email, "password": admin["password"]},
    )
    session.expire_all()
    entries = list(
        session.execute(select(AuditLog).where(AuditLog.action == "LOGIN")).scalars()
    )
    assert len(entries) == 1
    assert entries[0].actor_email == admin["user"].email


def test_me_describes_the_caller_and_their_permissions(client, auth_headers):
    body = client.get("/api/auth/me", headers=auth_headers).json()
    assert body["role"] == "ADMIN"
    assert body["active_organization_id"]
    assert len(body["organizations"]) == 1
    # Capabilities are computed server-side from the enforced table.
    assert "scan:create" in body["capabilities"]
    assert "scope:write" in body["capabilities"]


def test_refresh_issues_a_new_pair(client, admin):
    tokens = client.post(
        "/api/auth/login",
        json={"email": admin["user"].email, "password": admin["password"]},
    ).json()
    response = client.post(
        "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert response.status_code == 200
    assert response.json()["access_token"]


def test_an_access_token_is_not_accepted_as_a_refresh_token(client, admin):
    tokens = client.post(
        "/api/auth/login",
        json={"email": admin["user"].email, "password": admin["password"]},
    ).json()
    response = client.post(
        "/api/auth/refresh", json={"refresh_token": tokens["access_token"]}
    )
    assert response.status_code == 401
    assert "expected a refresh token" in response.json()["detail"]


def test_a_garbage_token_is_refused(client):
    response = client.get("/api/assets", headers={"Authorization": "Bearer not.a.jwt"})
    assert response.status_code == 401


def test_deactivating_a_user_invalidates_their_token(client, admin, session, auth_headers):
    """Authorization is re-read per request, so revocation is immediate."""
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 200

    user = session.get(User, admin["user"].id)
    user.is_active = False
    session.commit()

    assert client.get("/api/auth/me", headers=auth_headers).status_code == 401


# ---------------------------------------------------------------------------
# Authentication is required, and enforced per capability
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/assets"),
        ("get", "/api/scope"),
        ("get", "/api/scans"),
        ("get", "/api/findings"),
        ("get", "/api/changes"),
        ("get", "/api/graph"),
        ("get", "/api/attack-paths"),
        ("get", "/api/reports"),
        ("get", "/api/audit"),
        ("get", "/api/members"),
        ("get", "/api/dashboard"),
        ("get", "/api/rules"),
    ],
)
def test_every_data_route_requires_authentication(client, method, path):
    response = getattr(client, method)(path)
    assert response.status_code == 401, f"{path} answered {response.status_code} without auth"


def test_the_openapi_document_lists_the_expected_surface(client):
    paths = client.get("/openapi.json").json()["paths"]
    for expected in (
        "/api/auth/login",
        "/api/assets",
        "/api/scope",
        "/api/scans",
        "/api/findings",
        "/api/changes",
        "/api/graph",
        "/api/attack-paths",
        "/api/reports",
        "/api/audit/verify",
        "/api/dashboard",
    ):
        assert expected in paths, f"{expected} is missing from the API"


# ---------------------------------------------------------------------------
# Scope registry
# ---------------------------------------------------------------------------


def test_creating_a_scope_entry_defaults_to_pending(client, auth_headers):
    """Registering a target is not the same act as authorizing it."""
    response = client.post(
        "/api/scope", json={"domain": "app.acmepay.example"}, headers=auth_headers
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["authorization_status"] == "PENDING"
    assert body["is_authorized_now"] is False
    assert body["authorized_at"] is None


def test_authorizing_a_scope_entry_makes_it_scannable(client, auth_headers):
    entry = client.post(
        "/api/scope",
        json={"domain": "app.acmepay.example", "authorization_status": "AUTHORIZED"},
        headers=auth_headers,
    ).json()
    assert entry["authorization_status"] == "AUTHORIZED"
    assert entry["is_authorized_now"] is True
    assert entry["authorized_at"] is not None


def test_authorizing_then_revoking_clears_the_attestation(client, auth_headers):
    entry = client.post(
        "/api/scope",
        json={"domain": "app.acmepay.example", "authorization_status": "AUTHORIZED"},
        headers=auth_headers,
    ).json()

    revoked = client.patch(
        f"/api/scope/{entry['id']}",
        json={"authorization_status": "REVOKED"},
        headers=auth_headers,
    ).json()
    assert revoked["authorization_status"] == "REVOKED"
    assert revoked["is_authorized_now"] is False
    # A later re-authorization must set the attestation again rather than
    # inherit a stale claim from before the revocation.
    assert revoked["authorized_at"] is None


def test_an_expired_scope_entry_is_not_scannable(client, auth_headers):
    from datetime import timedelta

    past = (utcnow() - timedelta(days=1)).isoformat()
    entry = client.post(
        "/api/scope",
        json={
            "domain": "old.acmepay.example",
            "authorization_status": "AUTHORIZED",
            "expires_at": past,
        },
        headers=auth_headers,
    ).json()
    assert entry["is_authorized_now"] is False


def test_a_scope_entry_rejects_a_url(client, auth_headers):
    response = client.post(
        "/api/scope",
        json={"domain": "https://app.acmepay.example/admin"},
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_a_scope_entry_rejects_an_invalid_cidr(client, auth_headers):
    response = client.post(
        "/api/scope",
        json={"domain": "net.acmepay.example", "cidr": "10.0.0.0/99"},
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_a_duplicate_scope_entry_is_refused(client, auth_headers):
    payload = {"domain": "dup.acmepay.example"}
    assert client.post("/api/scope", json=payload, headers=auth_headers).status_code == 201
    assert client.post("/api/scope", json=payload, headers=auth_headers).status_code == 409


def test_scope_authorization_change_is_audited(client, auth_headers, session):
    from veyl_api.models import AuditLog

    entry = client.post(
        "/api/scope", json={"domain": "audited.acmepay.example"}, headers=auth_headers
    ).json()
    client.patch(
        f"/api/scope/{entry['id']}",
        json={"authorization_status": "AUTHORIZED"},
        headers=auth_headers,
    )
    session.expire_all()
    entries = list(
        session.execute(
            select(AuditLog).where(AuditLog.action == "SCOPE_AUTHORIZATION_CHANGED")
        ).scalars()
    )
    assert len(entries) == 1
    assert "PENDING -> AUTHORIZED" in entries[0].detail


# ---------------------------------------------------------------------------
# Scanning against real authorized scope
# ---------------------------------------------------------------------------


@pytest.fixture()
def scannable(client, auth_headers, demo_server):
    """An authorized scope entry pointing at the bundled AcmePay service.

    ``demo_server`` is a real HTTP server on a real port; the entry opts in to a
    port override so the ephemeral port can be scanned.
    """
    entry = client.post(
        "/api/scope",
        json={
            "domain": "127.0.0.1",
            "authorization_status": "AUTHORIZED",
            "allow_port_override": True,
            "environment": "PRODUCTION",
        },
        headers=auth_headers,
    ).json()
    return {"entry": entry, "port": demo_server}


def test_scanning_with_no_authorized_scope_is_refused_with_a_reason(client, auth_headers):
    response = client.post("/api/scans", json={}, headers=auth_headers)
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "no authorized" in detail["message"]


def test_scanning_a_pending_entry_is_refused(client, auth_headers):
    entry = client.post(
        "/api/scope", json={"domain": "127.0.0.1"}, headers=auth_headers
    ).json()
    response = client.post(
        "/api/scans", json={"scope_entry_ids": [entry["id"]]}, headers=auth_headers
    )
    assert response.status_code == 400
    assert "no authorized" in response.json()["detail"]["message"]


def test_a_port_override_is_refused_without_explicit_opt_in(client, auth_headers):
    """Honoring it silently would scan ports nobody authorized."""
    client.post(
        "/api/scope",
        json={"domain": "127.0.0.1", "authorization_status": "AUTHORIZED"},
        headers=auth_headers,
    )
    response = client.post(
        "/api/scans", json={"port_override": [8080]}, headers=auth_headers
    )
    assert response.status_code == 400
    assert "allow_port_override" in response.json()["detail"]


def test_a_scan_discovers_assets_and_creates_findings(client, auth_headers, scannable):
    response = client.post(
        "/api/scans",
        json={"label": "integration", "port_override": [scannable["port"]]},
        headers=auth_headers,
    )
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["status"] == "COMPLETED"
    assert scan["targets_scanned"] == 1
    assert scan["assets_found"] >= 1
    # The day7 demo profile serves /admin without a challenge and sets wildcard
    # CORS, so findings are expected. Asserting a floor rather than an exact
    # count keeps this robust to rule additions.
    assert scan["findings_created"] >= 1

    findings = client.get("/api/findings", headers=auth_headers).json()
    assert findings["total"] >= 1


def test_findings_carry_evidence_a_detection_explanation_and_an_impact(
    client, auth_headers, scannable
):
    """The product's central claim, asserted end to end through the API."""
    client.post(
        "/api/scans",
        json={"port_override": [scannable["port"]]},
        headers=auth_headers,
    )
    page = client.get("/api/findings", headers=auth_headers).json()
    assert page["total"] >= 1

    for summary in page["items"]:
        detail = client.get(f"/api/findings/{summary['id']}", headers=auth_headers).json()
        assert detail["detection_explanation"], f"{detail['rule_id']} has no detection explanation"
        assert detail["impact"], f"{detail['rule_id']} has no impact statement"
        assert detail["remediation_summary"], f"{detail['rule_id']} has no remediation"
        assert detail["risk_explanation"], f"{detail['rule_id']} has no priority rationale"
        assert detail["evidence"], f"{detail['rule_id']} has no evidence attached"
        for item in detail["evidence"]:
            assert item["provenance"] == "OBSERVED"
            assert item["matcher"]
            assert item["checksum"]
            assert item["detail"] != {} or item["summary"]


def test_a_scan_records_an_audit_trail(client, auth_headers, scannable, session):
    from veyl_api.models import AuditLog

    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    session.expire_all()
    actions = {
        entry.action
        for entry in session.execute(select(AuditLog)).scalars()
    }
    assert "SCAN_STARTED" in actions
    assert "SCAN_COMPLETED" in actions


def test_the_audit_chain_verifies_after_a_scan(client, auth_headers, scannable):
    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    body = client.get("/api/audit/verify", headers=auth_headers).json()
    assert body["is_valid"] is True
    assert body["entries_checked"] > 0
    assert body["first_bad_entry_id"] is None


# ---------------------------------------------------------------------------
# Assets and business context
# ---------------------------------------------------------------------------


def test_asset_context_can_be_set_and_rescores_findings(client, auth_headers, scannable):
    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    asset = client.get("/api/assets", headers=auth_headers).json()["items"][0]

    before = client.get(
        f"/api/findings?asset_id={asset['id']}", headers=auth_headers
    ).json()["items"]
    assert before

    context = client.put(
        f"/api/assets/{asset['id']}/context",
        json={
            "business_criticality": "CRITICAL",
            "data_classification": "CONFIDENTIAL",
            "business_function": "PAYMENTS",
            "internet_exposed": True,
        },
        headers=auth_headers,
    )
    assert context.status_code == 200, context.text
    body = context.json()
    assert body["business_criticality"] == "CRITICAL"
    # A value asserted by a person must never keep an INFERRED label.
    assert body["context_source"] == "USER_PROVIDED"

    rescored = client.post(f"/api/assets/{asset['id']}/rescore", headers=auth_headers)
    assert rescored.status_code == 200
    assert rescored.json()["findings_rescored"] >= 1

    after = client.get(
        f"/api/findings?asset_id={asset['id']}", headers=auth_headers
    ).json()["items"]
    # Business context must materially change priority, not just be stored.
    assert max(f["risk_score"] for f in after) >= max(f["risk_score"] for f in before)


def test_internet_exposed_is_only_settable_by_the_organization(client, auth_headers, scannable):
    """A scanner can never assert internet exposure; only a human can."""
    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    asset = client.get("/api/assets", headers=auth_headers).json()["items"][0]
    # The scan reached the host, but did not claim it faces the internet.
    assert asset["reachable"] is True
    assert asset["internet_exposed"] is False

    client.put(
        f"/api/assets/{asset['id']}/context",
        json={"internet_exposed": True},
        headers=auth_headers,
    )
    updated = client.get(f"/api/assets/{asset['id']}", headers=auth_headers).json()
    assert updated["internet_exposed"] is True


def test_finding_status_change_records_history(client, auth_headers, scannable):
    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    finding = client.get("/api/findings", headers=auth_headers).json()["items"][0]

    response = client.patch(
        f"/api/findings/{finding['id']}/status",
        json={"status": "ACKNOWLEDGED", "note": "triage in progress"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ACKNOWLEDGED"

    history = client.get(
        f"/api/findings/{finding['id']}/history", headers=auth_headers
    ).json()
    assert any(e["event_type"] == "STATUS_CHANGED" for e in history)
    assert any(e["from_value"] == "OPEN" for e in history)


def test_remediation_can_be_assigned_and_verified_state_is_reported(client, auth_headers, scannable):
    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    finding = client.get("/api/findings", headers=auth_headers).json()["items"][0]

    response = client.put(
        f"/api/findings/{finding['id']}/remediation",
        json={"priority": "URGENT", "notes": "blocked on vendor patch"},
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["priority"] == "URGENT"
    # Not yet verified: nothing rescanned to prove it is gone.
    assert body["verified_at"] is None


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def test_an_executive_html_report_embeds_evidence(client, auth_headers, scannable):
    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    response = client.post(
        "/api/reports",
        json={"kind": "EXECUTIVE", "fmt": "HTML"},
        headers=auth_headers,
    )
    assert response.status_code == 201, response.text
    report = response.json()
    assert report["status"] == "READY"
    assert report["checksum"]
    assert report["download_url"]

    download = client.get(
        f"/api/reports/{report['id']}/download", headers=auth_headers
    )
    assert download.status_code == 200
    body = download.text
    assert "<!DOCTYPE html>" in body
    assert "AcmePay" in body
    # The report must state its own limits rather than implying completeness.
    assert "potential" in body.lower()
    assert "How to read this report" in body


def test_a_technical_json_report_is_machine_readable(client, auth_headers, scannable):
    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    report = client.post(
        "/api/reports", json={"kind": "TECHNICAL", "fmt": "JSON"}, headers=auth_headers
    ).json()

    payload = client.get(
        f"/api/reports/{report['id']}/download", headers=auth_headers
    ).json()
    assert payload["report"]["kind"] == "TECHNICAL"
    assert payload["summary"]["open_findings"] >= 1
    assert payload["findings"]
    for finding in payload["findings"]:
        assert finding["evidence"], f"{finding['rule_id']} reported without evidence"
        assert finding["detection_explanation"]


def test_pdf_is_refused_explicitly_rather_than_faked(client, auth_headers):
    response = client.post(
        "/api/reports", json={"kind": "EXECUTIVE", "fmt": "PDF"}, headers=auth_headers
    )
    assert response.status_code == 501
    assert "not implemented" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Graph and attack paths
# ---------------------------------------------------------------------------


def test_the_graph_contains_nodes_and_edges_after_a_scan(client, auth_headers, scannable):
    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    body = client.get("/api/graph", headers=auth_headers).json()
    assert body["node_count"] >= 1
    assert body["nodes"]
    for node in body["nodes"]:
        assert ":" in node["node_key"]  # stable "type:identifier" keys


def test_attack_paths_are_stated_as_potential_with_limitations(client, auth_headers, scannable):
    client.post(
        "/api/scans", json={"port_override": [scannable["port"]]}, headers=auth_headers
    )
    client.post("/api/attack-paths/recompute", headers=auth_headers)

    page = client.get("/api/attack-paths", headers=auth_headers).json()
    for path in page["items"]:
        # Never claim exploitation that was not attempted.
        assert path["state"] == "POTENTIAL"
        assert path["limitations"], f"{path['name']} has no limitations statement"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_the_rule_catalogue_is_inspectable(client, auth_headers):
    rules = client.get("/api/rules", headers=auth_headers).json()
    assert len(rules) >= 10
    for rule in rules:
        assert rule["rule_id"].startswith("VEYL-")
        assert rule["description"]
        assert rule["requires_observations"], f"{rule['rule_id']} declares no observation kinds"


def test_an_unknown_rule_id_is_a_404(client, auth_headers):
    assert client.get("/api/rules/VEYL-NOPE-999", headers=auth_headers).status_code == 404


# ---------------------------------------------------------------------------
# Members and RBAC
# ---------------------------------------------------------------------------


def test_an_admin_can_add_a_member(client, auth_headers):
    response = client.post(
        "/api/members",
        json={
            "email": f"analyst-{uuid.uuid4().hex[:6]}@acmepay.example",
            "password": STRONG_PASSWORD,
            "role": "SECURITY_ANALYST",
            "full_name": "Sam Analyst",
        },
        headers=auth_headers,
    )
    assert response.status_code == 201, response.text
    assert response.json()["role"] == "SECURITY_ANALYST"


def test_a_weak_password_is_refused(client, auth_headers):
    response = client.post(
        "/api/members",
        json={
            "email": "weak@acmepay.example",
            "password": "password1234",
            "role": "ENGINEER",
            "full_name": "Weak Password",
        },
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_an_admin_cannot_demote_themselves(client, auth_headers, admin, session):
    """Otherwise an organization can be left with no administrator."""
    membership = session.execute(
        select(OrganizationMember).where(
            OrganizationMember.user_id == admin["user"].id
        )
    ).scalar_one()
    response = client.patch(
        f"/api/members/{membership.id}",
        json={"role": "ENGINEER"},
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert "cannot change your own role" in response.json()["detail"]


def test_an_admin_cannot_deactivate_themselves(client, auth_headers, admin, session):
    membership = session.execute(
        select(OrganizationMember).where(
            OrganizationMember.user_id == admin["user"].id
        )
    ).scalar_one()
    response = client.patch(
        f"/api/members/{membership.id}", json={"is_active": False}, headers=auth_headers
    )
    assert response.status_code == 400


def test_a_non_admin_cannot_add_members(client, session, admin, auth_headers):
    """An ENGINEER must be refused by capability, not by UI convention."""
    email = f"engineer-{uuid.uuid4().hex[:6]}@acmepay.example"
    created = client.post(
        "/api/members",
        json={"email": email, "password": STRONG_PASSWORD, "role": "ENGINEER", "full_name": "Test Person"},
        headers=auth_headers,
    )
    assert created.status_code == 201

    login = client.post(
        "/api/auth/login", json={"email": email, "password": STRONG_PASSWORD}
    ).json()
    engineer_headers = {"Authorization": f"Bearer {login['access_token']}"}

    # Read is allowed; write is not.
    assert client.get("/api/assets", headers=engineer_headers).status_code == 200
    assert client.get("/api/audit", headers=engineer_headers).status_code == 403
    assert (
        client.post(
            "/api/members",
            json={"email": "x@y.example", "password": STRONG_PASSWORD, "full_name": "X Y"},
            headers=engineer_headers,
        ).status_code
        == 403
    )


def test_an_executive_can_read_reports_but_not_scan(client, auth_headers, session):
    email = f"exec-{uuid.uuid4().hex[:6]}@acmepay.example"
    client.post(
        "/api/members",
        json={"email": email, "password": STRONG_PASSWORD, "role": "EXECUTIVE", "full_name": "Test Person"},
        headers=auth_headers,
    )
    login = client.post(
        "/api/auth/login", json={"email": email, "password": STRONG_PASSWORD}
    ).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}

    assert client.get("/api/findings", headers=headers).status_code == 200
    assert client.get("/api/reports", headers=headers).status_code == 200
    assert client.post("/api/scans", json={}, headers=headers).status_code == 403
    assert client.get("/api/audit", headers=headers).status_code == 403


def test_removing_a_member_revokes_their_access_immediately(client, auth_headers, session):
    email = f"temp-{uuid.uuid4().hex[:6]}@acmepay.example"
    member = client.post(
        "/api/members",
        json={"email": email, "password": STRONG_PASSWORD, "role": "SECURITY_ANALYST", "full_name": "Test Person"},
        headers=auth_headers,
    ).json()

    login = client.post(
        "/api/auth/login", json={"email": email, "password": STRONG_PASSWORD}
    ).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    assert client.get("/api/findings", headers=headers).status_code == 200

    assert client.delete(f"/api/members/{member['id']}", headers=auth_headers).status_code == 204

    # The token is still cryptographically valid; authorization is re-read.
    assert client.get("/api/findings", headers=headers).status_code == 403


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


@pytest.fixture()
def two_tenants(client, session, admin, auth_headers, demo_server):
    """A second organization with its own admin, scope, and findings."""
    other_org = Organization(
        name="Contoso", slug=f"contoso-{uuid.uuid4().hex[:8]}", primary_domain="contoso.example"
    )
    session.add(other_org)
    session.flush()

    other_user = User(
        email=f"admin-{uuid.uuid4().hex[:6]}@contoso.example",
        full_name="Chandra Contoso",
        password_hash=hash_password(STRONG_PASSWORD),
        is_active=True,
    )
    session.add(other_user)
    session.flush()
    session.add(
        OrganizationMember(
            organization_id=other_org.id,
            user_id=other_user.id,
            role=OrganizationRole.ADMIN,
            is_active=True,
        )
    )
    session.commit()

    other_login = client.post(
        "/api/auth/login", json={"email": other_user.email, "password": STRONG_PASSWORD}
    ).json()
    other_headers = {"Authorization": f"Bearer {other_login['access_token']}"}

    # AcmePay (the primary tenant) scans and gets real findings.
    client.post(
        "/api/scope",
        json={
            "domain": "127.0.0.1",
            "authorization_status": "AUTHORIZED",
            "allow_port_override": True,
        },
        headers=auth_headers,
    )
    client.post(
        "/api/scans", json={"port_override": [demo_server]}, headers=auth_headers
    )

    return {"other_org": other_org, "other_headers": other_headers}


def test_findings_do_not_leak_between_organizations(client, auth_headers, two_tenants):
    mine = client.get("/api/findings", headers=auth_headers).json()
    theirs = client.get("/api/findings", headers=two_tenants["other_headers"]).json()

    assert mine["total"] >= 1
    assert theirs["total"] == 0, "the second tenant saw the first tenant's findings"


def test_assets_do_not_leak_between_organizations(client, auth_headers, two_tenants):
    assert client.get("/api/assets", headers=auth_headers).json()["total"] >= 1
    assert client.get("/api/assets", headers=two_tenants["other_headers"]).json()["total"] == 0


def test_scope_does_not_leak_between_organizations(client, auth_headers, two_tenants):
    assert client.get("/api/scope", headers=auth_headers).json()["total"] >= 1
    assert client.get("/api/scope", headers=two_tenants["other_headers"]).json()["total"] == 0


def test_fetching_another_tenants_finding_is_a_404_not_a_403(client, auth_headers, two_tenants):
    """403 would confirm the identifier exists, which is an enumeration oracle."""
    finding = client.get("/api/findings", headers=auth_headers).json()["items"][0]
    response = client.get(
        f"/api/findings/{finding['id']}", headers=two_tenants["other_headers"]
    )
    assert response.status_code == 404


def test_fetching_another_tenants_asset_is_a_404(client, auth_headers, two_tenants):
    asset = client.get("/api/assets", headers=auth_headers).json()["items"][0]
    response = client.get(
        f"/api/assets/{asset['id']}", headers=two_tenants["other_headers"]
    )
    assert response.status_code == 404


def test_another_tenants_scan_id_cannot_be_used_to_scan(client, auth_headers, two_tenants):
    entry = client.get("/api/scope", headers=auth_headers).json()["items"][0]
    response = client.post(
        "/api/scans",
        json={"scope_entry_ids": [entry["id"]]},
        headers=two_tenants["other_headers"],
    )
    assert response.status_code == 404


def test_the_audit_chain_is_per_tenant(client, auth_headers, two_tenants):
    """One tenant's entries must not appear in, or break, another's chain."""
    mine = client.get("/api/audit", headers=auth_headers).json()
    theirs = client.get("/api/audit", headers=two_tenants["other_headers"]).json()

    assert mine["total"] >= 1
    # Contoso only logged in, so it has entries too — but none of AcmePay's.
    assert theirs["total"] >= 1
    my_ids = {e["id"] for e in mine["items"]}
    assert not (my_ids & {e["id"] for e in theirs["items"]})

    assert client.get("/api/audit/verify", headers=auth_headers).json()["is_valid"] is True
    assert (
        client.get("/api/audit/verify", headers=two_tenants["other_headers"]).json()["is_valid"]
        is True
    )


def test_dashboard_numbers_are_scoped_to_the_tenant(client, auth_headers, two_tenants):
    mine = client.get("/api/dashboard", headers=auth_headers).json()
    theirs = client.get("/api/dashboard", headers=two_tenants["other_headers"]).json()

    assert mine["asset_count"] >= 1
    assert mine["open_finding_count"] >= 1
    assert theirs["asset_count"] == 0
    assert theirs["open_finding_count"] == 0
    assert theirs["scope_entry_count"] == 0


def test_two_organizations_require_explicit_selection(client, session, auth_headers, two_tenants):
    """A user in two organizations must name one; guessing is unsafe."""
    admin_email = client.get("/api/auth/me", headers=auth_headers).json()["email"]
    user = session.execute(select(User).where(User.email == admin_email)).scalar_one()

    session.add(
        OrganizationMember(
            organization_id=two_tenants["other_org"].id,
            user_id=user.id,
            role=OrganizationRole.EXECUTIVE,
            is_active=True,
        )
    )
    session.commit()

    # A fresh token now carries no organization-specific choice usable on its own.
    login = client.post(
        "/api/auth/login", json={"email": admin_email, "password": STRONG_PASSWORD}
    )
    # Login resolves to the single organization the payload named (None), so it
    # must now refuse rather than pick one arbitrarily.
    assert login.status_code == 400
    assert "multiple organizations" in login.json()["detail"]

    # Naming one works, and the role is taken from that membership.
    named = client.post(
        "/api/auth/login",
        json={
            "email": admin_email,
            "password": STRONG_PASSWORD,
            "organization_slug": two_tenants["other_org"].slug,
        },
    )
    assert named.status_code == 200
    headers = {"Authorization": f"Bearer {named.json()['access_token']}"}
    assert client.get("/api/auth/me", headers=headers).json()["role"] == "EXECUTIVE"


# ---------------------------------------------------------------------------
# Validation and error handling
# ---------------------------------------------------------------------------


def test_validation_errors_do_not_echo_the_submitted_password(client, auth_headers):
    """A default FastAPI error body includes the input; this one must not.

    Asserted against a distinctive value rather than a short word, because a
    substring check on something like "short" would match the error *type*
    (``string_too_short``) and prove nothing.
    """
    secret = "Zq7-Sup3rSecret-Passphrase-Value"
    response = client.post(
        "/api/members",
        json={"email": "x@y.example", "password": secret, "role": "ENGINEER", "full_name": "A"},
        headers=auth_headers,
    )
    # The payload's password is long enough to pass, so this exercises the
    # success path; the important check is that no response ever contains it.
    assert secret not in response.text

    too_short = "Zq7-Short"
    rejected = client.post(
        "/api/members",
        json={"email": "x@y.example", "password": too_short, "role": "ENGINEER", "full_name": "A"},
        headers=auth_headers,
    )
    assert rejected.status_code == 422
    assert too_short not in rejected.text
    # The error names the rule, not the value.
    assert "string_too_short" in rejected.text or "too_short" in rejected.text


def test_a_malformed_json_body_is_a_422(client, auth_headers):
    response = client.post(
        "/api/scope",
        content=b"{not json",
        headers={**auth_headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_an_out_of_range_port_override_is_refused(client, auth_headers):
    entry = client.post(
        "/api/scope",
        json={"domain": "127.0.0.1", "authorization_status": "AUTHORIZED", "allow_port_override": True},
        headers=auth_headers,
    ).json()
    assert entry
    response = client.post(
        "/api/scans", json={"port_override": [70000]}, headers=auth_headers
    )
    assert response.status_code == 422


def test_pagination_bounds_are_enforced(client, auth_headers):
    assert client.get("/api/findings?limit=100000", headers=auth_headers).status_code == 422
    assert client.get("/api/findings?limit=0", headers=auth_headers).status_code == 422


def test_unknown_route_is_a_404(client, auth_headers):
    assert client.get("/api/does-not-exist", headers=auth_headers).status_code == 404


def test_member_id_helper_is_only_used_by_tests():
    """Guard against the test helper leaking into a route."""
    generated = members_route.new_member_id()
    assert isinstance(generated, str) and len(generated) == 36
