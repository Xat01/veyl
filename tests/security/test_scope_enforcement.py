"""Scope enforcement tests.

Scope is the authorization boundary: Veyl must not touch a host the organization
has not attested permission to assess. The subtlest failure mode here is
suffix matching that is not label-aware — ``notexample.com`` must never match a
scope entry for ``example.com`` — so that case is tested explicitly and from
several angles.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from veyl_api.db.base import utcnow
from veyl_api.enums import AssetOwner, AuthorizationStatus, Environment
from veyl_api.models import ScopeEntry
from veyl_api.safety.scope import ScopeGuard, domain_matches, ip_in_cidr


@pytest.mark.parametrize(
    "scope,hostname,expected",
    [
        # Exact and subdomain matches.
        ("example.com", "example.com", True),
        ("example.com", "api.example.com", True),
        ("example.com", "a.b.example.com", True),
        # The critical trap: a different registrable domain that merely ends
        # with the scope string must NOT match.
        ("example.com", "notexample.com", False),
        ("example.com", "example.com.evil.net", False),
        ("example.com", "evilexample.com", False),
        ("example.com", "anexample.com", False),
        # Case and trailing dot are normalised away.
        ("Example.COM", "api.example.com", True),
        ("example.com.", "api.example.com", True),
        # Wildcard entries authorize subdomains but not the apex itself.
        ("*.example.com", "api.example.com", True),
        ("*.example.com", "a.b.example.com", True),
        ("*.example.com", "example.com", False),
        ("*.example.com", "notexample.com", False),
        # Unrelated names.
        ("example.com", "example.net", False),
        ("example.com", "", False),
    ],
)
def test_domain_matches_is_label_aware(scope, hostname, expected):
    assert domain_matches(scope, hostname) is expected


@pytest.mark.parametrize(
    "cidr,ip_text,expected",
    [
        ("10.0.0.0/8", "10.1.2.3", True),
        ("10.0.0.0/8", "11.1.2.3", False),
        ("192.168.1.0/24", "192.168.1.55", True),
        ("192.168.1.0/24", "192.168.2.55", False),
        # Host bits set are accepted (strict=False normalises the network).
        ("192.168.1.5/24", "192.168.1.9", True),
        ("2001:db8::/32", "2001:db8::1", True),
        ("2001:db8::/32", "2001:db9::1", False),
        # Version mismatch must be a clean False, never an exception.
        ("10.0.0.0/8", "2001:db8::1", False),
        ("2001:db8::/32", "10.0.0.1", False),
        # Malformed input must not raise.
        ("not-a-cidr", "10.0.0.1", False),
        ("10.0.0.0/8", "not-an-ip", False),
    ],
)
def test_ip_in_cidr(cidr, ip_text, expected):
    assert ip_in_cidr(cidr, ip_text) is expected


def _entry(org_id, domain, **kwargs) -> ScopeEntry:
    defaults = {
        "organization_id": org_id,
        "domain": domain,
        "environment": Environment.PRODUCTION,
        "asset_owner": AssetOwner.ENGINEERING,
        "authorization_status": AuthorizationStatus.AUTHORIZED,
        "authorized_by": "test",
        "authorized_at": utcnow(),
    }
    defaults.update(kwargs)
    return ScopeEntry(**defaults)


def test_authorized_in_scope_target_is_allowed(session, organization):
    session.add(_entry(organization.id, "example.com"))
    session.commit()

    decision = ScopeGuard(session, organization.id).check("api.example.com")
    assert decision.allowed is True
    assert decision.match is not None
    assert decision.match.matched_by == "domain"


def test_pending_entry_is_refused_with_the_right_reason(session, organization):
    session.add(_entry(organization.id, "pending.example",
                       authorization_status=AuthorizationStatus.PENDING))
    session.commit()

    decision = ScopeGuard(session, organization.id).check("pending.example")
    assert decision.allowed is False
    assert decision.rejection.reason.value == "NOT_AUTHORIZED"
    assert "PENDING" in decision.rejection.detail


def test_revoked_entry_is_refused(session, organization):
    """A revoked attestation must stop authorizing immediately."""
    session.add(_entry(organization.id, "revoked.example",
                       authorization_status=AuthorizationStatus.REVOKED))
    session.commit()

    decision = ScopeGuard(session, organization.id).check("revoked.example")
    assert decision.allowed is False
    assert decision.rejection.reason.value == "NOT_AUTHORIZED"
    assert "REVOKED" in decision.rejection.detail


def test_expired_entry_is_refused(session, organization):
    session.add(_entry(organization.id, "expired.example",
                       expires_at=utcnow() - timedelta(days=1)))
    session.commit()

    decision = ScopeGuard(session, organization.id).check("expired.example")
    assert decision.allowed is False
    assert decision.rejection.reason.value == "SCOPE_EXPIRED"


def test_out_of_scope_target_is_refused(session, organization):
    session.add(_entry(organization.id, "example.com"))
    session.commit()

    decision = ScopeGuard(session, organization.id).check("other.net")
    assert decision.allowed is False
    assert decision.rejection.reason.value == "OUT_OF_SCOPE"
    assert "Scope Registry" in decision.rejection.detail


def test_inactive_entry_is_refused(session, organization):
    session.add(_entry(organization.id, "off.example", is_active=False))
    session.commit()

    decision = ScopeGuard(session, organization.id).check("off.example")
    assert decision.allowed is False


def test_cidr_entry_authorizes_an_ip_target(session, organization):
    session.add(_entry(organization.id, "10.0.0.0/8", cidr="10.0.0.0/8"))
    session.commit()

    decision = ScopeGuard(session, organization.id).check("10.4.5.6")
    assert decision.allowed is True
    assert decision.match.matched_by == "cidr"


def test_scope_does_not_leak_between_organizations(session, organization, other_organization):
    """Another tenant's scope entry must not authorize this tenant's target."""
    session.add(_entry(other_organization.id, "secret.example"))
    session.commit()

    decision = ScopeGuard(session, organization.id).check("secret.example")
    assert decision.allowed is False
    assert decision.rejection.reason.value == "OUT_OF_SCOPE"


def test_authorized_targets_excludes_unusable_entries(session, organization):
    session.add(_entry(organization.id, "good.example"))
    session.add(_entry(organization.id, "pending.example",
                       authorization_status=AuthorizationStatus.PENDING))
    session.add(_entry(organization.id, "expired.example",
                       expires_at=utcnow() - timedelta(days=1)))
    session.add(_entry(organization.id, "off.example", is_active=False))
    session.commit()

    usable = ScopeGuard(session, organization.id).authorized_targets()
    assert [e.domain for e in usable] == ["good.example"]
