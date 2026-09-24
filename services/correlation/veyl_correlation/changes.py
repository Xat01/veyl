"""Exposure change detection.

This is the feature the product is built around, so it gets the most careful
treatment. Change detection compares the :class:`AssetSnapshot` of the current
scan against the most recent previous snapshot for the same asset and emits a
typed :class:`ExposureChange` for every difference.

Design rules:

* **Detection is a pure function of two snapshots.** No network access, no
  clock dependence beyond the recorded timestamps. That is why it is fully
  testable and why a detected change is always reproducible from stored data.
* **A change needs evidence, exactly like a finding.** Every change carries the
  previous state, the current state, and the observation excerpt that supports
  it. "Port 8080 opened" without a prior state is not a change, it is an
  initial observation.
* **Business context is snapshotted onto the change.** If the asset is later
  reclassified, the change record still shows how it was classified when the
  change was detected, because that is what justified the priority at the time.
* **First observation is not a change.** The very first scan of an asset
  produces a baseline. Reporting everything as "new" on day one would be
  technically true and completely useless.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from veyl_api.db.base import utcnow
from veyl_api.enums import (
    RISK_INCREASING_CHANGES,
    BusinessCriticality,
    ChangeSignificance,
    ChangeType,
    DataClassification,
    Environment,
)
from veyl_api.models import Asset, AssetSnapshot, ExposureChange, Finding, FindingStatus, Scan


@dataclass
class ChangeDetectionResult:
    """Outcome of comparing two scans."""

    changes: list[ExposureChange] = field(default_factory=list)
    assets_compared: int = 0
    assets_without_baseline: int = 0
    previous_scan_id: str | None = None
    errors: list[str] = field(default_factory=list)


#: How alarming each change type is by default. Refined further by the asset's
#: business context in `_significance_for`.
BASE_SIGNIFICANCE: dict[ChangeType, ChangeSignificance] = {
    ChangeType.ASSET_ADDED: ChangeSignificance.NOTABLE,
    ChangeType.ASSET_REMOVED: ChangeSignificance.NOTABLE,
    ChangeType.PORT_OPENED: ChangeSignificance.SIGNIFICANT,
    ChangeType.PORT_CLOSED: ChangeSignificance.INFORMATIONAL,
    ChangeType.SERVICE_CHANGED: ChangeSignificance.SIGNIFICANT,
    ChangeType.SERVICE_VERSION_CHANGED: ChangeSignificance.NOTABLE,
    ChangeType.CERTIFICATE_CHANGED: ChangeSignificance.NOTABLE,
    ChangeType.CERTIFICATE_EXPIRING: ChangeSignificance.NOTABLE,
    ChangeType.CERTIFICATE_EXPIRED: ChangeSignificance.CRITICAL,
    ChangeType.DNS_CHANGED: ChangeSignificance.NOTABLE,
    ChangeType.HTTP_STATUS_CHANGED: ChangeSignificance.NOTABLE,
    ChangeType.SECURITY_HEADER_CHANGED: ChangeSignificance.NOTABLE,
    ChangeType.AUTHENTICATION_CHANGED: ChangeSignificance.SIGNIFICANT,
    ChangeType.FINDING_ADDED: ChangeSignificance.SIGNIFICANT,
    ChangeType.FINDING_RESOLVED: ChangeSignificance.INFORMATIONAL,
    ChangeType.FINDING_REOPENED: ChangeSignificance.SIGNIFICANT,
    ChangeType.TECH_ADDED: ChangeSignificance.INFORMATIONAL,
    ChangeType.TECH_REMOVED: ChangeSignificance.INFORMATIONAL,
}

#: Ports whose opening is materially more significant than an average new port.
_HIGH_IMPACT_PORTS = frozenset(
    {
        21, 22, 23, 445, 1433, 1521, 2375, 2376, 3306, 3389,
        5432, 5900, 5985, 5986, 6379, 6443, 9200, 10250, 11211, 27017,
    }
)


def _is_risk_increasing(
    change_type: ChangeType,
    *,
    previous_state: Any,
    current_state: Any,
    evidence: dict[str, Any],
) -> bool:
    """Decide whether a change moves the exposure in the wrong direction.

    Most change types are inherently one-directional: a port opening is a risk
    increase, a port closing is not. ``SECURITY_HEADER_CHANGED`` is not. The
    same change type covers both losing ``X-Frame-Options`` and gaining
    ``Content-Security-Policy``, and treating them alike would either hide a
    regression or manufacture an alarm. This function inspects the direction of
    the value change and answers the question properly.

    The result feeds the "risk-increasing" filter in the UI and the significance
    escalation, so getting it wrong makes the product either noisy or blind.
    """
    if change_type is not ChangeType.SECURITY_HEADER_CHANGED:
        return change_type in RISK_INCREASING_CHANGES

    header = str(evidence.get("header", "")).lower()
    before_raw = "" if previous_state is None else str(previous_state).strip()
    after_raw = "" if current_state is None else str(current_state).strip()

    # A header present in the previous scan and absent now is protection lost.
    if before_raw and not after_raw:
        return True
    # A header that was absent and is now set is protection gained.
    if not before_raw and after_raw:
        return False

    before = before_raw.lower()
    after = after_raw.lower()

    # CORS is the one header where "changed" needs a value-aware reading. These
    # are the transitions that widen who may read a response.
    if header.startswith("access-control-allow-origin"):
        if after == "*" and before != "*":
            return True
        if "*" in after and not before:
            return True
        if after and not before:
            return True
        if before and not after:
            return False

    if header.startswith("access-control-allow-credentials"):
        if after.lower() == "true" and before.lower() != "true":
            return True
        if before.lower() == "true" and after.lower() != "true":
            return False

    # For protective headers, a shorter or weaker value is a regression. The
    # comparison is deliberately crude: Veyl does not attempt to parse CSP or
    # HSTS semantics, and it says so rather than pretending to.
    if header in _PROTECTIVE_HEADERS:
        if len(after) < len(before):
            return True
        if _is_weaker_value(before, after):
            return True

    return False


#: Headers whose entire purpose is protection, so shrinking them is a regression.
_PROTECTIVE_HEADERS = frozenset(
    {
        "strict-transport-security",
        "x-frame-options",
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    }
)

#: Values that are strictly weaker than the ones they replaced.
_WEAKER_VALUES = {
    "sameorigin": {"deny"},
    "allow-from": {"deny", "sameorigin"},
    "unsafe-inline": set(),
    "nosniff": set(),
}


def _is_weaker_value(before: str, after: str) -> bool:
    """True when ``after`` is a known-weaker value than ``before``."""
    for weaker, stronger_set in _WEAKER_VALUES.items():
        if weaker in after and weaker not in before:
            if not stronger_set:
                return True
            if any(stronger in before for stronger in stronger_set):
                return True
    return False


def _significance_for(
    change_type: ChangeType,
    *,
    criticality: BusinessCriticality,
    environment: Environment,
    internet_exposed: bool,
    detail: dict[str, Any] | None = None,
    risk_increasing: bool | None = None,
) -> ChangeSignificance:
    """Raise significance when business context makes a change matter more.

    A new open port on a low-criticality development host is notable. The same
    change on a business-critical production host is significant. This function
    is the single place that decision is made, so it is easy to review and tune.

    ``risk_increasing`` lets the caller override the default derived from the
    change type. It exists because ``SECURITY_HEADER_CHANGED`` is bidirectional:
    losing a protective header and gaining one are the same type but opposite in
    meaning, and only the caller knows which happened.
    """
    base = BASE_SIGNIFICANCE.get(change_type, ChangeSignificance.INFORMATIONAL)
    levels = [
        ChangeSignificance.INFORMATIONAL,
        ChangeSignificance.NOTABLE,
        ChangeSignificance.SIGNIFICANT,
        ChangeSignificance.CRITICAL,
    ]
    index = levels.index(base)

    escalating = (
        risk_increasing
        if risk_increasing is not None
        else change_type in RISK_INCREASING_CHANGES
    )

    if escalating:
        if criticality is BusinessCriticality.CRITICAL:
            index = min(index + 1, len(levels) - 1)
        if environment is Environment.PRODUCTION and internet_exposed:
            index = min(index + 1, len(levels) - 1)

    # A newly opened high-impact port on an exposed host is significant
    # regardless of what the business context says.
    if change_type is ChangeType.PORT_OPENED and detail:
        try:
            port = int(detail.get("port"))
        except (TypeError, ValueError):
            port = -1
        if port in _HIGH_IMPACT_PORTS and internet_exposed:
            index = max(index, levels.index(ChangeSignificance.SIGNIFICANT))

    return levels[index]


def _security_significance(
    change_type: ChangeType,
    *,
    subject: str,
    previous_state: Any,
    current_state: Any,
    criticality: BusinessCriticality,
    environment: Environment,
    business_function: str,
) -> str:
    """Write the "why this matters" sentence for a change.

    Kept deliberately factual. It explains the security meaning of the observed
    difference without asserting an incident.
    """
    context_sentence = (
        f" This asset is classified {criticality.value} criticality and "
        f"{environment.value}, so a change here is weighted accordingly."
        if criticality in (BusinessCriticality.HIGH, BusinessCriticality.CRITICAL)
        else ""
    )

    if change_type is ChangeType.PORT_OPENED:
        return (
            f"{subject} became reachable where it was not reachable in the previous scan. "
            f"A port that opens without a corresponding change in intent is the most common way "
            f"an unintended service becomes exposed: a developer starts something to test it, "
            f"or a configuration change widens a rule more than intended. Reachability is by "
            f"itself the exposure; whether the service behind it is vulnerable is a separate "
            f"question answered by the findings on this asset."
            + context_sentence
        )
    if change_type is ChangeType.PORT_CLOSED:
        return (
            f"{subject} is no longer reachable. This reduces the attack surface. Veyl records it "
            f"so the reduction is attributable to a specific change rather than to a gap in "
            f"coverage."
        )
    if change_type is ChangeType.ASSET_ADDED:
        return (
            f"{subject} was discovered in this scan and was not present in the previous one. "
            f"A new asset is not a problem in itself, but an asset that nobody has reviewed has "
            f"no owner, no classification and no baseline. Veyl has assigned conservative "
            f"defaults; they should be reviewed."
            + context_sentence
        )
    if change_type is ChangeType.ASSET_REMOVED:
        return (
            f"{subject} stopped responding and was marked inactive. Confirm this was intended, "
            f"because a host that is decommissioned without being removed from DNS or from "
            f"application configuration is a dangling reference, and dangling references are "
            f"frequently claimable by a third party."
        )
    if change_type is ChangeType.SERVICE_CHANGED:
        return (
            f"The service listening on {subject} changed from {previous_state!r} to "
            f"{current_state!r}. A different service on the same port means a different set of "
            f"behaviours, versions and authentication boundaries, so any prior assessment of "
            f"that port no longer applies."
            + context_sentence
        )
    if change_type is ChangeType.SERVICE_VERSION_CHANGED:
        return (
            f"The version reported on {subject} changed from {previous_state!r} to "
            f"{current_state!r}. An upgrade usually reduces risk; a downgrade or an unexpected "
            f"change may indicate a rollback, a second host behind the same name, or tampering. "
            f"Veyl reports the change and does not assume which."
        )
    if change_type is ChangeType.CERTIFICATE_CHANGED:
        return (
            f"The TLS certificate presented on {subject} changed. Expected at renewal, and worth "
            f"confirming: an unexpected certificate change on a production service is a "
            f"substitution until proven otherwise. The new fingerprint and validity dates are "
            f"recorded in the evidence."
            + context_sentence
        )
    if change_type is ChangeType.CERTIFICATE_EXPIRED:
        return (
            f"The certificate on {subject} has passed its expiry date. Clients that validate "
            f"certificates will now fail to connect, and the usual operational response is to "
            f"accept or bypass the warning, which is the security consequence."
        )
    if change_type is ChangeType.CERTIFICATE_EXPIRING:
        return (
            f"The certificate on {subject} is approaching expiry. Recorded so renewal can be "
            f"planned rather than performed under pressure."
        )
    if change_type is ChangeType.DNS_CHANGED:
        return (
            f"The addresses {subject} resolves to changed from {previous_state!r} to "
            f"{current_state!r}. This can mean a deliberate migration, a load-balancer change, "
            f"or a hijack. Where the new address was not in scope, Veyl does not scan it and "
            f"records that it did not."
        )
    if change_type is ChangeType.HTTP_STATUS_CHANGED:
        return (
            f"The HTTP status for {subject} changed from {previous_state!r} to {current_state!r}. "
            f"A service that starts returning errors or unexpectedly starts returning 200 where "
            f"it previously required authentication is worth investigating."
            + context_sentence
        )
    if change_type is ChangeType.SECURITY_HEADER_CHANGED:
        return (
            f"A security header on {subject} changed from {previous_state!r} to {current_state!r}. "
            f"Security controls that weaken between scans indicate a configuration change, a "
            f"different backend, or a deployment that reverted a hardened baseline."
        )
    if change_type is ChangeType.AUTHENTICATION_CHANGED:
        return (
            f"The authentication challenge on {subject} changed from {previous_state!r} to "
            f"{current_state!r}. Losing an authentication challenge where one previously existed "
            f"is one of the highest-signal changes Veyl can observe."
            + context_sentence
        )
    if change_type is ChangeType.FINDING_ADDED:
        return (
            f"A new finding was raised on {subject} in this scan. The finding itself contains "
            f"the evidence and analysis."
        )
    if change_type is ChangeType.FINDING_RESOLVED:
        return (
            f"A previously open finding on {subject} did not reproduce in this scan and has been "
            f"marked resolved, with the scan recorded as verification evidence."
        )
    if change_type is ChangeType.FINDING_REOPENED:
        return (
            f"A finding on {subject} that had been marked resolved was detected again. Either the "
            f"remediation was incomplete or it was reverted. The reopen count is on the finding."
        )
    if change_type is ChangeType.TECH_ADDED:
        return (
            f"New technology was fingerprinted on {subject}: {current_state!r}. Recorded for "
            f"inventory; it is a change in the composition of the service, not by itself a risk."
        )
    if change_type is ChangeType.TECH_REMOVED:
        return (
            f"Technology previously fingerprinted on {subject} was no longer observed: "
            f"{previous_state!r}."
        )
    return f"An observed change was detected on {subject}."


def _risk_score_for(
    significance: ChangeSignificance,
    *,
    criticality: BusinessCriticality,
    data_classification: DataClassification,
    internet_exposed: bool,
) -> float:
    """Score a change for ordering the exposure-changes list."""
    base = {
        ChangeSignificance.INFORMATIONAL: 5.0,
        ChangeSignificance.NOTABLE: 25.0,
        ChangeSignificance.SIGNIFICANT: 50.0,
        ChangeSignificance.CRITICAL: 70.0,
    }[significance]

    if internet_exposed:
        base += 10.0
    if criticality is BusinessCriticality.CRITICAL:
        base += 12.0
    elif criticality is BusinessCriticality.HIGH:
        base += 7.0
    if data_classification in (DataClassification.CONFIDENTIAL, DataClassification.SENSITIVE):
        base += 6.0

    return round(min(base, 100.0), 1)


def _diff_values(previous: dict[str, Any], current: dict[str, Any], key: str) -> bool:
    """True when the value at ``key`` differs between the two states."""
    return previous.get(key) != current.get(key)


def detect_changes(
    session: Session,
    *,
    scan: Scan,
    previous_scan: Scan | None = None,
) -> ChangeDetectionResult:
    """Compare this scan's snapshots against the previous scan's snapshots."""
    result = ChangeDetectionResult()

    if previous_scan is not None:
        result.previous_scan_id = previous_scan.id

    current_snapshots = {
        snapshot.asset_id: snapshot
        for snapshot in session.execute(
            select(AssetSnapshot).where(
                AssetSnapshot.organization_id == scan.organization_id,
                AssetSnapshot.scan_id == scan.id,
            )
        ).scalars()
    }

    previous_snapshots: dict[str, AssetSnapshot] = {}
    if previous_scan is not None:
        previous_snapshots = {
            snapshot.asset_id: snapshot
            for snapshot in session.execute(
                select(AssetSnapshot).where(
                    AssetSnapshot.organization_id == scan.organization_id,
                    AssetSnapshot.scan_id == previous_scan.id,
                )
            ).scalars()
        }

    assets = {
        asset.id: asset
        for asset in session.execute(
            select(Asset).where(
                Asset.organization_id == scan.organization_id,
                Asset.id.in_(list(current_snapshots.keys()) or [""]),
            )
        ).scalars()
    }

    now = utcnow()

    for asset_id, current in current_snapshots.items():
        asset = assets.get(asset_id)
        if asset is None:
            continue

        previous = previous_snapshots.get(asset_id)

        if previous is None:
            # No baseline: this asset is newly observed in its entirety. Record
            # a single ASSET_ADDED change rather than a diff against nothing,
            # because "everything is new" carries no information.
            result.assets_without_baseline += 1
            if previous_snapshots or previous_scan is not None:
                result.changes.append(
                    _make_change(
                        asset=asset,
                        scan=scan,
                        previous_scan=previous_scan,
                        change_type=ChangeType.ASSET_ADDED,
                        subject=asset.asset_key,
                        previous_state="not observed",
                        current_state=(
                            f"reachable on {len(current.state.get('ports', []))} port(s): "
                            f"{', '.join(str(p) for p in current.state.get('ports', [])[:10]) or 'none'}"
                        ),
                        evidence={
                            "snapshot_hash": current.state_hash,
                            "ports": current.state.get("ports", []),
                            "services": current.state.get("services", {}),
                            "detection_basis": (
                                "The asset appears in this scan's snapshots and had no snapshot in "
                                "the previous scan. The previous state is stated as 'not observed' "
                                "because Veyl has no prior observation of it."
                            ),
                        },
                        now=now,
                    )
                )
            continue

        if previous.state_hash == current.state_hash:
            result.assets_compared += 1
            continue

        result.assets_compared += 1
        result.changes.extend(
            _diff_asset(asset=asset, previous=previous, current=current, scan=scan,
                        previous_scan=previous_scan, now=now)
        )

    # Findings that changed state in this scan are also changes.
    result.changes.extend(
        _detect_finding_changes(session, scan=scan, assets=assets, now=now)
    )

    for change in result.changes:
        session.add(change)
    session.flush()

    return result


def _diff_asset(
    *,
    asset: Asset,
    previous: AssetSnapshot,
    current: AssetSnapshot,
    scan: Scan,
    previous_scan: Scan | None,
    now: datetime,
) -> list[ExposureChange]:
    """Emit one change per observable difference for a single asset."""
    changes: list[ExposureChange] = []
    prev_state = previous.state or {}
    curr_state = current.state or {}

    def add(
        change_type: ChangeType,
        subject: str,
        previous_state: Any,
        current_state: Any,
        evidence: dict[str, Any],
    ) -> None:
        changes.append(
            _make_change(
                asset=asset,
                scan=scan,
                previous_scan=previous_scan,
                change_type=change_type,
                subject=subject,
                previous_state=previous_state,
                current_state=current_state,
                evidence=evidence,
                now=now,
            )
        )

    # --- Ports -------------------------------------------------------------
    prev_ports = set(prev_state.get("ports") or [])
    curr_ports = set(curr_state.get("ports") or [])

    for port in sorted(curr_ports - prev_ports):
        service = (curr_state.get("services") or {}).get(str(port))
        add(
            ChangeType.PORT_OPENED,
            f"{asset.asset_key}:{port}",
            "closed",
            "open",
            {
                "port": port,
                "previous_ports": sorted(prev_ports),
                "current_ports": sorted(curr_ports),
                "service_signature": service,
                "snapshot_hash_before": previous.state_hash,
                "snapshot_hash_after": current.state_hash,
                "detection_basis": (
                    f"TCP/{port} is absent from the previous scan's open-port set and present in "
                    f"this scan's."
                ),
            },
        )

    for port in sorted(prev_ports - curr_ports):
        add(
            ChangeType.PORT_CLOSED,
            f"{asset.asset_key}:{port}",
            "open",
            "closed",
            {
                "port": port,
                "previous_ports": sorted(prev_ports),
                "current_ports": sorted(curr_ports),
                "snapshot_hash_before": previous.state_hash,
                "snapshot_hash_after": current.state_hash,
                "detection_basis": (
                    f"TCP/{port} is present in the previous scan's open-port set and absent from "
                    f"this scan's."
                ),
            },
        )

    # --- Services ----------------------------------------------------------
    prev_services = prev_state.get("services") or {}
    curr_services = curr_state.get("services") or {}

    for port_key in sorted(set(prev_services) | set(curr_services)):
        before = prev_services.get(port_key)
        after = curr_services.get(port_key)
        if before == after:
            continue
        if before is None or after is None:
            # The port itself opened or closed; already reported above.
            continue

        before_name, _, before_rest = str(before).partition("|")
        after_name, _, after_rest = str(after).partition("|")

        if before_name != after_name:
            add(
                ChangeType.SERVICE_CHANGED,
                f"{asset.asset_key}:{port_key}",
                before_name,
                after_name,
                {
                    "port": int(port_key) if port_key.isdigit() else port_key,
                    "previous_signature": before,
                    "current_signature": after,
                    "detection_basis": (
                        "The service name component of the fingerprint signature changed."
                    ),
                },
            )
        elif before_rest != after_rest:
            add(
                ChangeType.SERVICE_VERSION_CHANGED,
                f"{asset.asset_key}:{port_key}",
                before_rest or "unknown",
                after_rest or "unknown",
                {
                    "port": int(port_key) if port_key.isdigit() else port_key,
                    "previous_signature": before,
                    "current_signature": after,
                    "detection_basis": (
                        "The product or version component of the fingerprint signature changed."
                    ),
                },
            )

    # --- Certificate -------------------------------------------------------
    prev_cert = prev_state.get("certificate") or {}
    curr_cert = curr_state.get("certificate") or {}

    if prev_cert.get("fingerprint") and curr_cert.get("fingerprint"):
        if prev_cert["fingerprint"] != curr_cert["fingerprint"]:
            add(
                ChangeType.CERTIFICATE_CHANGED,
                f"{asset.asset_key}:{curr_cert.get('not_after', '')}",
                f"fingerprint {prev_cert['fingerprint'][:16]}",
                f"fingerprint {curr_cert['fingerprint'][:16]}",
                {
                    "previous": prev_cert,
                    "current": curr_cert,
                    "detection_basis": (
                        "The SHA-256 fingerprint of the presented certificate differs between the "
                        "two scans."
                    ),
                },
            )
    elif prev_cert and curr_cert and prev_cert.get("not_after") != curr_cert.get("not_after"):
        add(
            ChangeType.CERTIFICATE_CHANGED,
            f"{asset.asset_key}:certificate",
            prev_cert,
            curr_cert,
            {
                "previous": prev_cert,
                "current": curr_cert,
                "detection_basis": "Certificate validity dates changed between scans.",
            },
        )

    # --- HTTP --------------------------------------------------------------
    prev_http = prev_state.get("http") or {}
    curr_http = curr_state.get("http") or {}

    if (
        prev_http.get("status_code") is not None
        and curr_http.get("status_code") is not None
        and prev_http["status_code"] != curr_http["status_code"]
    ):
        add(
            ChangeType.HTTP_STATUS_CHANGED,
            f"{asset.asset_key}:/",
            f"HTTP {prev_http['status_code']}",
            f"HTTP {curr_http['status_code']}",
            {
                "previous": prev_http,
                "current": curr_http,
                "detection_basis": "The status code of a request to / differed between scans.",
            },
        )

    # --- Security headers --------------------------------------------------
    prev_headers = prev_state.get("security_headers") or {}
    curr_headers = curr_state.get("security_headers") or {}

    for header in sorted(set(prev_headers) | set(curr_headers)):
        before = prev_headers.get(header)
        after = curr_headers.get(header)
        if before == after:
            continue

        # A header that disappeared is a weakening; report it distinctly.
        weakened = bool(before) and not after
        change_type = (
            ChangeType.AUTHENTICATION_CHANGED
            if header in ("www-authenticate",)
            else ChangeType.SECURITY_HEADER_CHANGED
        )
        add(
            change_type,
            f"{asset.asset_key}:{header}",
            before or "absent",
            after or "absent",
            {
                "header": header,
                "previous_value": before,
                "current_value": after,
                "weakened": weakened,
                "previous_headers": prev_headers,
                "current_headers": curr_headers,
                "detection_basis": f"The value of the {header} response header changed.",
            },
        )

    # --- DNS ---------------------------------------------------------------
    prev_dns = prev_state.get("dns_a")
    curr_dns = curr_state.get("dns_a")
    if prev_dns is not None and curr_dns is not None and prev_dns != curr_dns:
        add(
            ChangeType.DNS_CHANGED,
            f"{asset.asset_key}:A",
            ", ".join(prev_dns) or "none",
            ", ".join(curr_dns) or "none",
            {
                "previous_records": prev_dns,
                "current_records": curr_dns,
                "detection_basis": "The set of A records for the hostname changed between scans.",
                "note": (
                    "Veyl only scans addresses that are inside authorized scope. Where a new "
                    "address is outside scope it was not probed and is recorded here without "
                    "assessment."
                ),
            },
        )

    # --- Technology --------------------------------------------------------
    prev_tech = set(prev_state.get("tech") or [])
    curr_tech = set(curr_state.get("tech") or [])
    for tech in sorted(curr_tech - prev_tech):
        add(
            ChangeType.TECH_ADDED,
            f"{asset.asset_key}:{tech}",
            "not observed",
            tech,
            {"technology": tech, "previous": sorted(prev_tech), "current": sorted(curr_tech)},
        )
    for tech in sorted(prev_tech - curr_tech):
        add(
            ChangeType.TECH_REMOVED,
            f"{asset.asset_key}:{tech}",
            tech,
            "not observed",
            {"technology": tech, "previous": sorted(prev_tech), "current": sorted(curr_tech)},
        )

    return changes


def _detect_finding_changes(
    session: Session,
    *,
    scan: Scan,
    assets: dict[str, Asset],
    now: datetime,
) -> list[ExposureChange]:
    """Surface finding lifecycle transitions as exposure changes."""
    changes: list[ExposureChange] = []

    findings = list(
        session.execute(
            select(Finding).where(
                Finding.organization_id == scan.organization_id,
                Finding.last_scan_id == scan.id,
            )
        ).scalars()
    )

    for finding in findings:
        asset = assets.get(finding.asset_id)
        if asset is None:
            continue

        created_here = finding.first_scan_id == scan.id
        resolved_here = (
            finding.status is FindingStatus.RESOLVED and finding.last_scan_id == scan.id
        )
        reopened = finding.reopen_count > 0 and created_here is False and finding.status is FindingStatus.OPEN

        if created_here:
            changes.append(
                _make_change(
                    asset=asset,
                    scan=scan,
                    previous_scan=None,
                    change_type=ChangeType.FINDING_ADDED,
                    subject=f"{asset.asset_key}:{finding.rule_id}",
                    previous_state="no finding",
                    current_state=f"{finding.severity.value} {finding.title}",
                    evidence={
                        "finding_id": finding.id,
                        "rule_id": finding.rule_id,
                        "severity": finding.severity.value,
                        "confidence": finding.confidence.value,
                        "risk_score": finding.risk_score,
                    },
                    now=now,
                )
            )
        if resolved_here:
            changes.append(
                _make_change(
                    asset=asset,
                    scan=scan,
                    previous_scan=None,
                    change_type=ChangeType.FINDING_RESOLVED,
                    subject=f"{asset.asset_key}:{finding.rule_id}",
                    previous_state=f"{finding.severity.value} {finding.title}",
                    current_state="resolved",
                    evidence={
                        "finding_id": finding.id,
                        "rule_id": finding.rule_id,
                        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
                        "verification": (
                            "The rule did not reproduce in a scan that covered this asset."
                        ),
                    },
                    now=now,
                )
            )
        if reopened:
            changes.append(
                _make_change(
                    asset=asset,
                    scan=scan,
                    previous_scan=None,
                    change_type=ChangeType.FINDING_REOPENED,
                    subject=f"{asset.asset_key}:{finding.rule_id}",
                    previous_state="resolved",
                    current_state=f"{finding.severity.value} {finding.title} (reopened)",
                    evidence={
                        "finding_id": finding.id,
                        "rule_id": finding.rule_id,
                        "reopen_count": finding.reopen_count,
                    },
                    now=now,
                )
            )

    return changes


def _make_change(
    *,
    asset: Asset,
    scan: Scan,
    previous_scan: Scan | None,
    change_type: ChangeType,
    subject: str,
    previous_state: Any,
    current_state: Any,
    evidence: dict[str, Any],
    now: datetime,
) -> ExposureChange:
    """Construct one ExposureChange with business context snapshotted onto it."""
    detail = evidence if isinstance(evidence, dict) else {}
    risk_increasing = _is_risk_increasing(
        change_type,
        previous_state=previous_state,
        current_state=current_state,
        evidence=detail,
    )
    significance = _significance_for(
        change_type,
        criticality=asset.business_criticality,
        environment=asset.environment,
        internet_exposed=asset.internet_exposed,
        detail=detail,
        risk_increasing=risk_increasing,
    )

    return ExposureChange(
        organization_id=asset.organization_id,
        scan_id=scan.id,
        previous_scan_id=previous_scan.id if previous_scan else None,
        asset_id=asset.id,
        change_type=change_type,
        significance=significance,
        subject=subject[:255],
        previous_state=str(previous_state)[:4000],
        current_state=str(current_state)[:4000],
        evidence=detail,
        security_significance=_security_significance(
            change_type,
            subject=subject,
            previous_state=previous_state,
            current_state=current_state,
            criticality=asset.business_criticality,
            environment=asset.environment,
            business_function=asset.business_function.value,
        ),
        asset_criticality=asset.business_criticality,
        asset_environment=asset.environment,
        business_function=asset.business_function,
        internet_exposed=asset.internet_exposed,
        is_risk_increasing=risk_increasing,
        risk_score=_risk_score_for(
            significance,
            criticality=asset.business_criticality,
            data_classification=asset.data_classification,
            internet_exposed=asset.internet_exposed,
        ),
        detected_at=now,
    )
