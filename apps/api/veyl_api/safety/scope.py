"""Scope enforcement — the authorization boundary.

Two independent gates must pass before Veyl touches a host:

1. **Network safety floor** (``firewall``) — is this address one we are willing
   to speak to at all?
2. **Scope guard** (this module) — has the organization explicitly attested
   permission to assess *this specific* host, and is that attestation still
   valid?

A target passing one gate but not the other is refused, and the refusal reason
is recorded on the scan rather than swallowed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from veyl_api.db.base import utcnow
from veyl_api.enums import AuthorizationStatus
from veyl_api.models import ScopeEntry
from veyl_api.safety.firewall import (
    TargetRejection,
    TargetRejectionReason,
    normalize_hostname,
)


@dataclass
class ScopeMatch:
    """The scope entry that authorized a target."""

    entry: ScopeEntry
    matched_by: str  # "domain" | "cidr"


@dataclass
class ScopeDecision:
    """Outcome of a scope check."""

    target: str
    allowed: bool
    match: ScopeMatch | None = None
    rejection: TargetRejection | None = None
    #: All scope entries that matched, including unusable ones, for reporting.
    candidate_entries: list[ScopeEntry] = field(default_factory=list)


def _is_expired(entry: ScopeEntry, now: datetime) -> bool:
    return entry.expires_at is not None and entry.expires_at <= now


def domain_matches(scope_domain: str, hostname: str) -> bool:
    """Return True when ``hostname`` is ``scope_domain`` or a subdomain of it.

    Matching is on label boundaries, so ``notexample.com`` does **not** match a
    scope entry for ``example.com``. This is the single most common way scope
    checks are implemented incorrectly, so it is centralised here and tested.
    """
    scope = normalize_hostname(scope_domain)
    host = normalize_hostname(hostname)

    if not scope or not host:
        return False
    if host == scope:
        return True
    # A wildcard scope entry "*.example.com" authorizes subdomains only.
    if scope.startswith("*."):
        base = scope[2:]
        return host.endswith("." + base) and host != base
    return host.endswith("." + scope)


def ip_in_cidr(cidr: str, ip_text: str) -> bool:
    """Return True when ``ip_text`` falls inside ``cidr``. False on any error."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    # Comparing across families raises; treat as no match.
    if network.version != addr.version:
        return False
    return addr in network


class ScopeGuard:
    """Answers "is this organization authorized to assess this target?"

    Instances are cheap and bound to one organization. The guard loads scope
    entries once and caches them for the lifetime of a scan, so a scan cannot
    observe a scope change mid-run.
    """

    def __init__(self, session: Session, organization_id: str) -> None:
        self.session = session
        self.organization_id = organization_id
        self._entries: list[ScopeEntry] | None = None

    def all_entries(self, *, include_inactive: bool = False) -> list[ScopeEntry]:
        """Load all scope entries for the organization, newest first."""
        if self._entries is None:
            stmt = (
                select(ScopeEntry)
                .where(ScopeEntry.organization_id == self.organization_id)
                .order_by(ScopeEntry.created_at.desc())
            )
            self._entries = list(self.session.execute(stmt).scalars())
        if include_inactive:
            return self._entries
        return [e for e in self._entries if e.is_active]

    def refresh(self) -> None:
        """Drop the cache. Call after mutating scope within the same session."""
        self._entries = None

    def check(
        self,
        target: str,
        *,
        resolved_addresses: list[str] | None = None,
        now: datetime | None = None,
    ) -> ScopeDecision:
        """Decide whether ``target`` is inside authorized scope.

        Both the hostname and every resolved address are checked. An IP that
        falls inside an authorized CIDR is sufficient on its own; otherwise the
        hostname must match an authorized domain entry.
        """
        now = now or utcnow()
        host = normalize_hostname(target)
        entries = self.all_entries()

        candidates: list[ScopeEntry] = []
        authorized: ScopeEntry | None = None
        matched_by = ""

        for entry in entries:
            domain_hit = domain_matches(entry.domain, host)
            cidr_hit = False
            if not domain_hit and entry.cidr:
                addresses = resolved_addresses or []
                cidr_hit = any(ip_in_cidr(entry.cidr, a) for a in addresses)
                # A bare IP target should also match a CIDR entry directly.
                if not cidr_hit:
                    cidr_hit = ip_in_cidr(entry.cidr, host)

            if not (domain_hit or cidr_hit):
                continue

            candidates.append(entry)

            if authorized is not None:
                continue

            if entry.authorization_status is not AuthorizationStatus.AUTHORIZED:
                continue
            if _is_expired(entry, now):
                continue
            if not entry.is_active:
                continue

            authorized = entry
            matched_by = "domain" if domain_hit else "cidr"

        if authorized is not None:
            return ScopeDecision(
                target=target,
                allowed=True,
                match=ScopeMatch(entry=authorized, matched_by=matched_by),
                candidate_entries=candidates,
            )

        # Build a specific, actionable rejection reason.
        if not candidates:
            rejection = TargetRejection(
                target,
                TargetRejectionReason.OUT_OF_SCOPE,
                "no scope entry covers this target; add it to the Scope Registry and "
                "mark it AUTHORIZED before scanning",
            )
        else:
            entry = candidates[0]
            if entry.authorization_status is not AuthorizationStatus.AUTHORIZED:
                rejection = TargetRejection(
                    target,
                    TargetRejectionReason.NOT_AUTHORIZED,
                    f"scope entry {entry.domain!r} exists but its authorization status is "
                    f"{entry.authorization_status.value}",
                )
            elif _is_expired(entry, now):
                expiry = entry.expires_at.isoformat() if entry.expires_at else "unknown"
                rejection = TargetRejection(
                    target,
                    TargetRejectionReason.SCOPE_EXPIRED,
                    f"scope entry {entry.domain!r} expired at {expiry}",
                )
            elif not entry.is_active:
                rejection = TargetRejection(
                    target,
                    TargetRejectionReason.OUT_OF_SCOPE,
                    f"scope entry {entry.domain!r} is deactivated",
                )
            else:
                rejection = TargetRejection(
                    target,
                    TargetRejectionReason.OUT_OF_SCOPE,
                    f"scope entry {entry.domain!r} did not authorize this target",
                )

        return ScopeDecision(
            target=target, allowed=False, rejection=rejection, candidate_entries=candidates
        )

    def resolve_scope_entry_for(self, target: str, resolved_addresses: list[str] | None = None) -> ScopeEntry | None:
        """Return the authorizing entry for a target, or None."""
        decision = self.check(target, resolved_addresses=resolved_addresses)
        return decision.match.entry if decision.match else None

    def authorized_targets(self, *, now: datetime | None = None) -> list[ScopeEntry]:
        """All scope entries that are currently usable."""
        now = now or utcnow()
        return [
            e
            for e in self.all_entries()
            if e.authorization_status is AuthorizationStatus.AUTHORIZED
            and not _is_expired(e, now)
            and e.is_active
        ]
