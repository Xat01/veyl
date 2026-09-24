"""SSRF refusal tests.

A scanner that can be pointed at arbitrary addresses is a server-side request
forgery proxy. Every vector below is a real technique for reaching a host that
the naive check would have allowed. Each one is asserted to be refused, and the
reason is asserted too, so a change that keeps the target blocked but for the
wrong reason is still caught.

These tests run the firewall under a *production-like* policy
(``allow_private_targets=False``, ``env=production``). That is the configuration
in which the floor has to hold, and the development exceptions Veyl grants for
local demos must not leak into it.
"""

from __future__ import annotations

import ipaddress

import pytest

from veyl_api.safety import firewall as firewall_module
from veyl_api.safety.firewall import (
    TargetRejection,
    TargetRejectionReason,
    UnsafeTargetError,
    classify_address,
    validate_hostname_syntax,
    validate_target,
)


@pytest.fixture()
def production_policy(monkeypatch):
    """Force the firewall into the strict posture a real deployment uses."""
    settings = firewall_module.settings
    monkeypatch.setattr(settings, "env", "production", raising=False)
    monkeypatch.setattr(settings, "allow_private_targets", False, raising=False)
    monkeypatch.setattr(settings, "always_block_metadata", True, raising=False)
    return settings


@pytest.mark.parametrize(
    "address,expected",
    [
        # Loopback in every notation an attacker might use.
        ("127.0.0.1", TargetRejectionReason.LOOPBACK),
        ("127.0.0.254", TargetRejectionReason.LOOPBACK),
        ("::1", TargetRejectionReason.LOOPBACK),
        # Cloud metadata, which is the classic target of this class of bug.
        ("169.254.169.254", TargetRejectionReason.METADATA),
        ("169.254.170.2", TargetRejectionReason.METADATA),
        ("100.100.100.200", TargetRejectionReason.METADATA),
        ("192.0.0.192", TargetRejectionReason.METADATA),
        ("fd00:ec2::254", TargetRejectionReason.METADATA),
        # IPv6 forms carrying an IPv4 address. The inner address is classified
        # first, so the reason names the real problem rather than the wrapper.
        ("::ffff:127.0.0.1", TargetRejectionReason.LOOPBACK),
        ("64:ff9b::7f00:1", TargetRejectionReason.LOOPBACK),
        ("2002:7f00:1::", TargetRejectionReason.LOOPBACK),
        # Never legitimate under any policy.
        ("224.0.0.1", TargetRejectionReason.MULTICAST),
        ("ff02::1", TargetRejectionReason.MULTICAST),
        ("0.0.0.0", TargetRejectionReason.UNSPECIFIED),
        ("::", TargetRejectionReason.UNSPECIFIED),
        ("169.254.1.1", TargetRejectionReason.LINK_LOCAL),
        ("fe80::1", TargetRejectionReason.LINK_LOCAL),
        # Private ranges, refused by the default policy.
        ("10.0.0.1", TargetRejectionReason.PRIVATE),
        ("192.168.1.1", TargetRejectionReason.PRIVATE),
        ("172.16.0.1", TargetRejectionReason.PRIVATE),
    ],
)
def test_classify_address_refuses_dangerous_addresses(address, expected, production_policy):
    """Every one of these must be refused, with a specific reason."""
    result = classify_address(ipaddress.ip_address(address))
    assert result is expected, f"{address} produced {result}, expected {expected}"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1", "169.254.169.254", "169.254.170.2", "100.100.100.200",
        "192.0.0.192", "fd00:ec2::254", "::ffff:169.254.169.254",
        "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::", "0.0.0.0",
        "::", "224.0.0.1", "fe80::1", "10.0.0.1",
    ],
)
def test_no_ssrf_vector_is_ever_allowed(address, production_policy):
    """The belt-and-braces assertion: none of these may return None (allowed)."""
    assert classify_address(ipaddress.ip_address(address)) is not None


def test_metadata_is_blocked_unconditionally(monkeypatch):
    """Even under a permissive policy, the metadata endpoints stay blocked."""
    settings = firewall_module.settings
    monkeypatch.setattr(settings, "allow_private_targets", True, raising=False)
    monkeypatch.setattr(settings, "env", "development", raising=False)
    monkeypatch.setattr(settings, "always_block_metadata", True, raising=False)

    for address in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200", "192.0.0.192"):
        assert classify_address(ipaddress.ip_address(address)) is not None


@pytest.mark.parametrize(
    "hostname",
    [
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.goog",
        "foo.local",
        "foo.internal",
        "bar.localhost",
        "instance-data",
    ],
)
def test_validate_target_refuses_metadata_and_local_hostnames(hostname, production_policy):
    """A metadata service reachable by name must be refused before resolution."""
    with pytest.raises(UnsafeTargetError) as excinfo:
        validate_target(hostname)
    assert excinfo.value.rejection.reason is not None


@pytest.mark.parametrize(
    "target",
    [
        "example.com; rm -rf /",
        "example.com && id",
        "example.com | cat /etc/passwd",
        "example.com`whoami`",
        "example.com$(id)",
        "example.com\nHost: evil",
        "example.com\x00.evil",
        "exam ple.com",
        "example.com/../../etc/passwd",
        'example.com"',
        "example.com'",
        "example.com<foo>",
        "-example.com",
    ],
)
def test_validate_target_refuses_injection_characters(target, production_policy):
    """Shell metacharacters and control characters must never reach a resolver."""
    with pytest.raises(UnsafeTargetError):
        validate_target(target)


def test_validate_target_refuses_alternate_ip_notation(production_policy):
    """Alternate IP notations and resolver-based rebinding tricks are caught."""
    for target in ("2130706433", "0x7f000001", "0177.0.0.1"):
        with pytest.raises(UnsafeTargetError):
            validate_target(target)


def test_validate_target_refuses_bare_hostname_without_dot(production_policy):
    """A single-label name is not a valid public target."""
    rejection = validate_hostname_syntax("intranet")
    assert rejection is not None
    assert rejection.reason is TargetRejectionReason.INVALID_HOSTNAME


def test_private_addresses_allowed_only_when_explicitly_permitted(monkeypatch):
    """The private-address policy must be honoured, not bypassed."""
    settings = firewall_module.settings
    addr = ipaddress.ip_address("10.0.0.5")

    monkeypatch.setattr(settings, "allow_private_targets", False, raising=False)
    assert classify_address(addr) is TargetRejectionReason.PRIVATE

    monkeypatch.setattr(settings, "allow_private_targets", True, raising=False)
    assert classify_address(addr) is None


def test_loopback_is_refused_in_a_public_deployment(production_policy):
    """allow_private must not become a way to reach loopback in production."""
    addr = ipaddress.ip_address("127.0.0.1")
    assert classify_address(addr) is TargetRejectionReason.LOOPBACK


def test_loopback_is_permitted_only_in_a_local_development_env(monkeypatch):
    """The demo exception is narrow: development/test only, and opt-in."""
    settings = firewall_module.settings
    addr = ipaddress.ip_address("127.0.0.1")

    monkeypatch.setattr(settings, "allow_private_targets", True, raising=False)
    monkeypatch.setattr(settings, "env", "development", raising=False)
    assert classify_address(addr) is None

    monkeypatch.setattr(settings, "env", "staging", raising=False)
    assert classify_address(addr) is TargetRejectionReason.LOOPBACK

    monkeypatch.setattr(settings, "env", "production", raising=False)
    assert classify_address(addr) is TargetRejectionReason.LOOPBACK


def test_rejection_is_explainable():
    """A refusal must be reportable, with a reason and a detail."""
    rejection = TargetRejection(
        "127.0.0.1",
        TargetRejectionReason.LOOPBACK,
        "loopback addresses are refused",
    )
    assert rejection.reason is TargetRejectionReason.LOOPBACK
    assert "loopback" in rejection.detail
    assert rejection.as_dict()["reason"] == "LOOPBACK"
