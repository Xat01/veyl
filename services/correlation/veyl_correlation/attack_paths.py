"""Attack-path correlation.

An attack path is a *plausible* chain of conditions that compound. Veyl's
language discipline matters more here than anywhere else in the product, because
this is the feature most likely to be over-claimed.

The rules of engagement:

* Every path is ``POTENTIAL`` unless a specific, authorized, non-destructive
  check produced positive evidence. Veyl does not have such checks in this
  version, so every path it emits is ``POTENTIAL`` and the UI must say so.
* Every step cites the finding or observation that supports it. A step with no
  evidence does not appear.
* Every path carries a ``limitations`` field stating what Veyl did *not* verify.
* A path never asserts exploitation. The summary sentence is written so that
  reading it in isolation cannot mislead.

The patterns below are deliberately conservative. A pattern fires only when
every one of its preconditions is present with real evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from veyl_api.db.base import utcnow
from veyl_api.enums import (
    ACTIVE_FINDING_STATUSES,
    AttackPathState,
    BusinessCriticality,
    Confidence,
    DataClassification,
    Environment,
)
from veyl_api.models import Asset, AttackPath, Finding, Scan

#: Rules that indicate an administrative or management interface is reachable.
ADMIN_INTERFACE_RULES = frozenset(
    {"VEYL-NET-002", "VEYL-AUTH-001", "VEYL-API-003", "VEYL-INFRA-001", "VEYL-INFRA-002"}
)

#: Rules that indicate an authentication boundary weakness.
AUTH_WEAKNESS_RULES = frozenset(
    {"VEYL-AUTH-001", "VEYL-AUTH-002", "VEYL-API-001", "VEYL-WEB-009"}
)

#: Rules indicating a data store is reachable.
DATA_STORE_RULES = frozenset({"VEYL-NET-001", "VEYL-AUTH-002"})

#: Rules indicating sensitive content is retrievable.
DISCLOSURE_RULES = frozenset({"VEYL-WEB-011", "VEYL-WEB-010", "VEYL-WEB-012"})


@dataclass
class PathStep:
    """One link in a chain, with the evidence that supports it."""

    order: int
    description: str
    finding_id: str | None
    rule_id: str | None
    asset_id: str
    evidence_summary: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "description": self.description,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "asset_id": self.asset_id,
            "evidence_summary": self.evidence_summary,
        }


@dataclass
class CorrelatedPath:
    """A candidate attack path before persistence."""

    name: str
    summary: str
    state: AttackPathState
    confidence: Confidence
    risk_score: float
    asset_ids: list[str]
    finding_ids: list[str]
    steps: list[PathStep]
    business_impact: str
    limitations: str


def correlate_attack_paths(
    session: Session, *, organization_id: str, scan: Scan | None = None
) -> list[AttackPath]:
    """Evaluate every pattern and persist the correlated paths."""
    active_findings = list(
        session.execute(
            select(Finding).where(
                Finding.organization_id == organization_id,
                Finding.status.in_([s.value for s in ACTIVE_FINDING_STATUSES]),
            )
        ).scalars()
    )
    assets = {
        asset.id: asset
        for asset in session.execute(
            select(Asset).where(Asset.organization_id == organization_id)
        ).scalars()
    }

    by_asset: dict[str, list[Finding]] = {}
    for finding in active_findings:
        by_asset.setdefault(finding.asset_id, []).append(finding)

    candidates: list[CorrelatedPath] = []

    for asset_id, findings in by_asset.items():
        asset = assets.get(asset_id)
        if asset is None:
            continue
        candidates.extend(_evaluate_patterns(asset, findings))

    # Replace the previous set so a path that no longer holds disappears.
    for existing in session.execute(
        select(AttackPath).where(AttackPath.organization_id == organization_id)
    ).scalars():
        session.delete(existing)
    session.flush()

    now = utcnow()
    persisted: list[AttackPath] = []
    for candidate in candidates:
        path = AttackPath(
            organization_id=organization_id,
            name=candidate.name[:300],
            summary=candidate.summary,
            state=candidate.state,
            confidence=candidate.confidence,
            risk_score=candidate.risk_score,
            node_keys=[],
            steps=[step.as_dict() for step in candidate.steps],
            finding_ids=candidate.finding_ids,
            asset_ids=candidate.asset_ids,
            business_impact=candidate.business_impact,
            limitations=candidate.limitations,
            is_active=True,
            last_evaluated_scan_id=scan.id if scan else None,
            detected_at=now,
        )
        session.add(path)
        persisted.append(path)

    session.flush()
    return persisted


def _risk_score(
    *,
    criticality: BusinessCriticality,
    data_classification: DataClassification,
    environment: Environment,
    internet_exposed: bool,
    step_count: int,
) -> float:
    score = 25.0
    if criticality is BusinessCriticality.CRITICAL:
        score += 25.0
    elif criticality is BusinessCriticality.HIGH:
        score += 15.0
    if data_classification in (DataClassification.CONFIDENTIAL, DataClassification.SENSITIVE):
        score += 12.0
    if environment is Environment.PRODUCTION:
        score += 8.0
    if internet_exposed:
        score += 10.0
    score += min(step_count * 2.0, 10.0)
    return round(min(score, 100.0), 1)


def _evaluate_patterns(asset: Asset, findings: list[Finding]) -> list[CorrelatedPath]:
    """Run every correlation pattern against one asset's findings."""
    paths: list[CorrelatedPath] = []

    by_rule = {finding.rule_id: finding for finding in findings}
    admin_findings = [f for f in findings if f.rule_id in ADMIN_INTERFACE_RULES]
    auth_findings = [f for f in findings if f.rule_id in AUTH_WEAKNESS_RULES]
    data_findings = [f for f in findings if f.rule_id in DATA_STORE_RULES]
    disclosure_findings = [f for f in findings if f.rule_id in DISCLOSURE_RULES]

    context_phrase = (
        f"The asset is classified {asset.business_criticality.value} business criticality, "
        f"{asset.data_classification.value} data classification, and runs in "
        f"{asset.environment.value}."
    )

    # ------------------------------------------------------------------
    # Pattern 1: administrative interface + weak auth boundary + sensitive asset
    # ------------------------------------------------------------------
    if admin_findings and auth_findings:
        admin = admin_findings[0]
        auth = auth_findings[0]
        steps = [
            PathStep(
                order=1,
                description=(
                    f"An administrative or management interface is reachable on "
                    f"{asset.asset_key}."
                ),
                finding_id=admin.id,
                rule_id=admin.rule_id,
                asset_id=asset.id,
                evidence_summary=admin.description,
            ),
            PathStep(
                order=2,
                description=(
                    "The authentication or authorization boundary around it is weak or was not "
                    "observed to be enforced."
                ),
                finding_id=auth.id,
                rule_id=auth.rule_id,
                asset_id=asset.id,
                evidence_summary=auth.description,
            ),
        ]
        if asset.business_criticality in (BusinessCriticality.HIGH, BusinessCriticality.CRITICAL):
            steps.append(
                PathStep(
                    order=3,
                    description=(
                        f"Reaching this interface grants access to a system the organization has "
                        f"classified {asset.business_criticality.value} criticality."
                    ),
                    finding_id=None,
                    rule_id="VEYL-EXP-001",
                    asset_id=asset.id,
                    evidence_summary=(
                        f"Business criticality {asset.business_criticality.value}, data "
                        f"classification {asset.data_classification.value}, established by the "
                        f"organization with provenance {asset.context_source.value}."
                    ),
                )
            )

        paths.append(
            CorrelatedPath(
                name=f"Administrative interface with a weak boundary on {asset.asset_key}",
                summary=(
                    f"Veyl observed that {asset.asset_key} exposes an administrative interface "
                    f"({admin.title.lower()}) and separately detected a condition affecting its "
                    f"authentication or authorization boundary ({auth.title.lower()}). Taken "
                    f"together these form a potential path from an unauthenticated network "
                    f"position to administrative control of the asset. Veyl has confirmed each "
                    f"condition independently through the evidence on the linked findings. Veyl "
                    f"has NOT attempted to authenticate, to bypass the boundary, or to access the "
                    f"interface. This is a potential attack path, not a demonstrated compromise."
                ),
                state=AttackPathState.POTENTIAL,
                confidence=Confidence.MEDIUM,
                risk_score=_risk_score(
                    criticality=asset.business_criticality,
                    data_classification=asset.data_classification,
                    environment=asset.environment,
                    internet_exposed=asset.internet_exposed,
                    step_count=len(steps),
                ),
                asset_ids=[asset.id],
                finding_ids=[admin.id, auth.id],
                steps=steps,
                business_impact=(
                    f"An administrative interface on {asset.asset_key} controls the application "
                    f"and its data rather than a single record. If the boundary were crossed, "
                    f"impact would be bounded by what the interface can do: configuration change, "
                    f"data access, or in the case of a container control plane, the host itself. "
                    f"{context_phrase} The classification is the organization's own; Veyl did not "
                    f"determine it."
                ),
                limitations=(
                    "Veyl did not attempt authentication against the interface, did not attempt to "
                    "bypass or defeat the boundary, and did not verify that the two conditions are "
                    "actually combinable. The weak-boundary condition may be mitigated by a "
                    "control Veyl cannot observe from outside, such as network ACLs, an "
                    "authentication proxy, or device posture. Treat this as a hypothesis that "
                    "deserves a human review, not as a confirmed route."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Pattern 2: reachable data store + sensitive data classification
    # ------------------------------------------------------------------
    if data_findings and asset.data_classification in (
        DataClassification.CONFIDENTIAL,
        DataClassification.SENSITIVE,
    ):
        data_finding = data_findings[0]
        steps = [
            PathStep(
                order=1,
                description=f"A data store is reachable on {asset.asset_key}.",
                finding_id=data_finding.id,
                rule_id=data_finding.rule_id,
                asset_id=asset.id,
                evidence_summary=data_finding.description,
            ),
            PathStep(
                order=2,
                description=(
                    f"The asset is classified as holding {asset.data_classification.value} data."
                ),
                finding_id=None,
                rule_id=None,
                asset_id=asset.id,
                evidence_summary=(
                    f"Data classification {asset.data_classification.value} with provenance "
                    f"{asset.context_source.value}."
                ),
            ),
        ]

        paths.append(
            CorrelatedPath(
                name=(
                    f"Reachable data store holding {asset.data_classification.value.lower()} data on "
                    f"{asset.asset_key}"
                ),
                summary=(
                    f"Veyl observed a reachable data store on {asset.asset_key} and that the "
                    f"organization classifies this asset as holding "
                    f"{asset.data_classification.value.lower()} data. Where the store is "
                    f"reachable and the classification is accurate, a single successful "
                    f"authentication would expose data of that sensitivity in bulk. Veyl has "
                    f"confirmed reachability. Veyl has NOT attempted to authenticate to the "
                    f"store, to enumerate databases, or to read any data. This is a potential "
                    f"path, not a demonstrated access."
                ),
                state=AttackPathState.POTENTIAL,
                confidence=Confidence.MEDIUM,
                risk_score=_risk_score(
                    criticality=asset.business_criticality,
                    data_classification=asset.data_classification,
                    environment=asset.environment,
                    internet_exposed=asset.internet_exposed,
                    step_count=len(steps),
                ),
                asset_ids=[asset.id],
                finding_ids=[data_finding.id],
                steps=steps,
                business_impact=(
                    f"Bulk data of {asset.data_classification.value.lower()} sensitivity is the "
                    f"kind of loss that carries notification obligations and regulatory "
                    f"consequence, rather than an operational outage. {context_phrase}"
                ),
                limitations=(
                    "Veyl did not attempt to authenticate or read data. The reachability finding "
                    "does not establish that authentication is absent or weak, only that the "
                    "service is reachable. If the data classification is stale, the assessed "
                    "impact is overstated."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Pattern 3: exposed configuration + any reachable production surface
    # ------------------------------------------------------------------
    if disclosure_findings and asset.environment is Environment.PRODUCTION:
        disclosure = disclosure_findings[0]
        steps = [
            PathStep(
                order=1,
                description=(
                    f"Content that should not be public is retrievable from {asset.asset_key}."
                ),
                finding_id=disclosure.id,
                rule_id=disclosure.rule_id,
                asset_id=asset.id,
                evidence_summary=disclosure.description,
            ),
            PathStep(
                order=2,
                description=(
                    "Anything disclosed here is directly usable by anyone who can reach the "
                    "public URL, without further interaction."
                ),
                finding_id=None,
                rule_id=None,
                asset_id=asset.id,
                evidence_summary=(
                    "The disclosure findings carry the retrieved content prefix as evidence, so "
                    "the extent of the exposure can be assessed directly."
                ),
            ),
        ]

        paths.append(
            CorrelatedPath(
                name=f"Public disclosure on production asset {asset.asset_key}",
                summary=(
                    f"Veyl retrieved content from {asset.asset_key} that is not intended to be "
                    f"public. Unlike the other paths Veyl reports, this one requires no further "
                    f"step: the content was retrieved during the scan and is recorded as evidence "
                    f"on the linked finding. The exposure is present, not potential. What remains "
                    f"unverified is the consequence, which depends on what the content contains "
                    f"and whether the credentials in it are still valid."
                ),
                state=AttackPathState.POTENTIAL,
                confidence=Confidence.HIGH,
                risk_score=min(
                    _risk_score(
                        criticality=asset.business_criticality,
                        data_classification=asset.data_classification,
                        environment=asset.environment,
                        internet_exposed=asset.internet_exposed,
                        step_count=len(steps),
                    )
                    + 10.0,
                    100.0,
                ),
                asset_ids=[asset.id],
                finding_ids=[disclosure.id],
                steps=steps,
                business_impact=(
                    f"Content retrieved from a production asset is disclosed to everyone who can "
                    f"reach the URL. Where it contains credentials, assume they are already "
                    f"compromised. {context_phrase}"
                ),
                limitations=(
                    "Veyl retrieved the content and recorded a bounded prefix as evidence. It did "
                    "not extract, enumerate or test any credential found, and it did not "
                    "determine whether the disclosed values are live. The stated state remains "
                    "POTENTIAL because Veyl does not assert exploitation, even where the exposure "
                    "itself is directly observed."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Pattern 4: exposed control plane + anything else on the same asset
    # ------------------------------------------------------------------
    control_plane = by_rule.get("VEYL-INFRA-001")
    if control_plane is not None and len(findings) > 1:
        others = [f for f in findings if f.id != control_plane.id][:2]
        steps = [
            PathStep(
                order=1,
                description=(
                    "A container or orchestration control plane is reachable. Crossing this "
                    "boundary grants control of the host or cluster rather than a single service."
                ),
                finding_id=control_plane.id,
                rule_id=control_plane.rule_id,
                asset_id=asset.id,
                evidence_summary=control_plane.description,
            )
        ]
        for index, other in enumerate(others, start=2):
            steps.append(
                PathStep(
                    order=index,
                    description=(
                        f"A second, independent condition exists on the same host: "
                        f"{other.title}."
                    ),
                    finding_id=other.id,
                    rule_id=other.rule_id,
                    asset_id=asset.id,
                    evidence_summary=other.description,
                )
            )

        paths.append(
            CorrelatedPath(
                name=f"Exposed control plane on {asset.asset_key}",
                summary=(
                    f"Veyl observed a reachable container or orchestration control plane on "
                    f"{asset.asset_key}"
                    + (
                        f", alongside {len(others)} other finding(s) on the same host."
                        if others
                        else "."
                    )
                    + " A reachable control plane is categorically worse than a reachable "
                    "application service, because successful access grants control of the host "
                    "and therefore of every service on it. Veyl has confirmed reachability only. "
                    "It has not attempted to authenticate to the control plane or to invoke any "
                    "API operation."
                ),
                state=AttackPathState.POTENTIAL,
                confidence=Confidence.MEDIUM,
                risk_score=min(
                    _risk_score(
                        criticality=asset.business_criticality,
                        data_classification=asset.data_classification,
                        environment=asset.environment,
                        internet_exposed=asset.internet_exposed,
                        step_count=len(steps),
                    )
                    + 10.0,
                    100.0,
                ),
                asset_ids=[asset.id],
                finding_ids=[control_plane.id, *(f.id for f in others)],
                steps=steps,
                business_impact=(
                    f"Control of this host implies control of every workload on it, including "
                    f"their access to data and to other systems through their credentials. "
                    f"{context_phrase}"
                ),
                limitations=(
                    "Veyl did not attempt to authenticate to the control plane and did not invoke "
                    "any management operation. Reachability does not establish that the control "
                    "plane is unauthenticated; where it is correctly configured it requires a "
                    "client certificate or a token. Treat the exposure as a priority for review "
                    "and the path as a hypothesis."
                ),
            )
        )

    return paths
