"""Analyzer: turns rule matches into persisted findings.

Pipeline position::

    observations -> rule engine -> matches -> analyzer -> findings + evidence

The analyzer is where a match becomes a durable, auditable record. Two things
matter here:

* **Evidence is copied, not generated.** Each finding's evidence rows hold a
  verbatim excerpt of the observation the rule cited, plus a checksum. The
  checksum lets a report reader confirm the evidence has not changed since the
  finding was raised.
* **Deduplication is stable across scans.** A finding's identity is derived from
  (rule, asset, subject), so a finding that disappears and returns is *reopened*
  rather than duplicated. That is what makes the verification story work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from veyl_api.db.base import utcnow
from veyl_api.enums import (
    ACTIVE_FINDING_STATUSES,
    Confidence,
    FindingStatus,
    Provenance,
)
from veyl_api.models import (
    Asset,
    AssetContext,
    Evidence,
    Finding,
    FindingEvent,
    Observation,
    Scan,
)
from veyl_api.security.sanitize import checksum, truncate
from veyl_rules import RuleContext, RuleMatch, evaluate
from veyl_rules.framework import RuleDefinition
from veyl_analyzer.risk import RiskAssessment, assess_risk


@dataclass
class AnalyzerResult:
    """Summary of one analyze_scan call."""

    findings_created: int = 0
    findings_updated: int = 0
    findings_reopened: int = 0
    findings_resolved: int = 0
    evidence_rows: int = 0
    rules_evaluated: int = 0
    rules_skipped: int = 0
    rejections: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def build_rule_context(
    asset: Asset,
    asset_context: AssetContext | None,
    observations: list[Observation],
) -> RuleContext:
    """Assemble the read-only view a rule is allowed to see.

    Only observations for this asset from this scan are included. A rule cannot
    reach any other asset, any other scan, or any other tenant.
    """
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for observation in observations:
        payload = dict(observation.data or {})
        payload.setdefault("subject", observation.subject)
        payload.setdefault("observation_id", observation.id)
        payload.setdefault("confidence", observation.confidence.value if observation.confidence else None)
        payload.setdefault("provenance", observation.provenance.value if observation.provenance else None)
        by_kind.setdefault(observation.kind, []).append(payload)

    # Business context is exposed as its own pseudo-observation so rules can
    # cite it as evidence and the evaluator's "kind must be present" check
    # passes legitimately.
    if asset_context is not None:
        by_kind["business_context"] = [
            {
                "subject": asset.asset_key,
                "business_criticality": asset.business_criticality.value,
                "data_classification": asset.data_classification.value,
                "business_function": asset.business_function.value,
                "environment": asset.environment.value,
                "owner": asset.owner.value,
                "context_source": asset_context.context_source.value,
                "context_confidence": asset_context.context_confidence.value,
                "business_description": asset_context.business_description,
            }
        ]
    else:
        by_kind["business_context"] = [
            {
                "subject": asset.asset_key,
                "business_criticality": asset.business_criticality.value,
                "data_classification": asset.data_classification.value,
                "business_function": asset.business_function.value,
                "environment": asset.environment.value,
                "context_source": asset.source_provenance.value,
            }
        ]

    return RuleContext(
        by_kind=by_kind,
        business_criticality=asset.business_criticality.value,
        data_classification=asset.data_classification.value,
        environment=asset.environment.value,
        business_function=asset.business_function.value,
        internet_exposed=asset.internet_exposed,
        asset_key=asset.asset_key,
        hostname=asset.hostname,
    )


def _dedup_key(rule_id: str, asset_id: str, subject_suffix: str) -> str:
    """Stable finding identity across scans."""
    suffix = subject_suffix or "default"
    return f"{rule_id}:{asset_id}:{suffix}"


def _match_detail_for_evidence(
    match: RuleMatch, entry: dict[str, Any], observations: list[Observation]
) -> tuple[Observation | None, dict[str, Any]]:
    """Resolve a rule's evidence reference to the observation it read.

    The rule names a kind and a matcher; the analyzer looks up the concrete
    observation row so the stored evidence can point at real source data rather
    than at the rule's own restatement of it.
    """
    kind = str(entry.get("kind"))
    detail = entry.get("detail")
    if not isinstance(detail, dict):
        detail = {"observed": str(detail)}

    # Find an observation of the cited kind that actually contains the values
    # the rule relied on. Where the rule supplied a port, use it to disambiguate
    # between multiple observations of the same kind.
    candidates = [o for o in observations if o.kind == kind]
    if not candidates:
        return None, detail

    wanted_port = detail.get("port")
    if wanted_port is not None:
        for observation in candidates:
            if (observation.data or {}).get("port") == wanted_port:
                return observation, detail

    wanted_subject = detail.get("subject")
    if wanted_subject is not None:
        for observation in candidates:
            if observation.subject == str(wanted_subject):
                return observation, detail

    return candidates[0], detail


def _build_evidence(
    *,
    organization_id: str,
    finding: Finding,
    match: RuleMatch,
    observations: list[Observation],
    scan: Scan,
) -> list[Evidence]:
    """Create evidence rows for one finding, each tied to a real observation."""
    rows: list[Evidence] = []
    for entry in match.evidence:
        observation, detail = _match_detail_for_evidence(match, entry, observations)
        summary = f"{entry.get('kind')}: {entry.get('matcher')}"
        safe_detail = detail
        digest = checksum(safe_detail)

        rows.append(
            Evidence(
                organization_id=organization_id,
                finding_id=finding.id,
                observation_id=observation.id if observation else None,
                scan_id=scan.id,
                kind=str(entry.get("kind", "unknown")),
                summary=truncate(summary, 500),
                detail=safe_detail,
                matcher=truncate(str(entry.get("matcher", "")), 200),
                provenance=(
                    observation.provenance if observation else Provenance.OBSERVED
                ),
                confidence=(
                    observation.confidence if observation else Confidence.MEDIUM
                ),
                observed_at=observation.observed_at if observation else (scan.started_at or utcnow()),
                checksum=digest,
            )
        )
    return rows


def _new_finding(
    *,
    organization_id: str,
    asset: Asset,
    scan: Scan,
    rule: RuleDefinition,
    match: RuleMatch,
    assessment: RiskAssessment,
    now: datetime,
) -> Finding:
    severity = match.severity or rule.severity
    confidence = match.confidence or rule.default_confidence
    return Finding(
        organization_id=organization_id,
        dedup_key=_dedup_key(rule.rule_id, asset.id, match.subject_suffix),
        asset_id=asset.id,
        rule_id=rule.rule_id,
        rule_category=rule.category,
        title=rule.title,
        severity=severity,
        confidence=confidence,
        status=FindingStatus.OPEN,
        description=match.summary or rule.description,
        detection_explanation=match.detection_explanation,
        impact=match.impact,
        remediation_summary=rule.remediation,
        references=rule.references,
        vulnerability_refs=match.vulnerability_refs,
        risk_score=assessment.score,
        risk_factors=assessment.factors,
        risk_explanation=assessment.explanation,
        criticality_boost=assessment.criticality_boost,
        first_seen_at=now,
        last_seen_at=now,
        first_scan_id=scan.id,
        last_scan_id=scan.id,
    )


def analyze_scan(
    session: Session,
    *,
    scan: Scan,
    persist: bool = True,
) -> AnalyzerResult:
    """Evaluate every rule against every asset observed in this scan."""
    result = AnalyzerResult()
    organization_id = scan.organization_id

    observations = list(
        session.execute(
            select(Observation).where(
                Observation.organization_id == organization_id,
                Observation.scan_id == scan.id,
            )
        ).scalars()
    )

    by_asset: dict[str, list[Observation]] = {}
    for observation in observations:
        if observation.asset_id:
            by_asset.setdefault(observation.asset_id, []).append(observation)

    if not by_asset:
        return result

    assets = {
        asset.id: asset
        for asset in session.execute(
            select(Asset).where(
                Asset.organization_id == organization_id,
                Asset.id.in_(list(by_asset.keys())),
            )
        ).scalars()
    }

    contexts = {
        context.asset_id: context
        for context in session.execute(
            select(AssetContext).where(
                AssetContext.organization_id == organization_id,
                AssetContext.asset_id.in_(list(by_asset.keys())),
            )
        ).scalars()
    }

    now = utcnow()
    matched_keys: set[str] = set()

    for asset_id, asset_observations in by_asset.items():
        asset = assets.get(asset_id)
        if asset is None:
            continue

        context = build_rule_context(asset, contexts.get(asset_id), asset_observations)
        report = evaluate(context)
        result.rules_evaluated += report.result.evaluated
        result.rules_skipped += len(report.result.skipped)
        for rejection in report.rejections:
            result.rejections.append(
                {
                    "rule_id": rejection.rule_id,
                    "reason": rejection.reason,
                    "match": rejection.match_summary,
                }
            )

        for rule, match in report.matches:
            dedup_key = _dedup_key(rule.rule_id, asset.id, match.subject_suffix)
            matched_keys.add(dedup_key)

            existing = session.execute(
                select(Finding).where(
                    Finding.organization_id == organization_id,
                    Finding.dedup_key == dedup_key,
                )
            ).scalar_one_or_none()

            open_port_count = len((context.first("port_scan") or {}).get("open_ports", []) or [])

            assessment = assess_risk(
                rule=rule,
                match=match,
                asset=asset,
                business_criticality=asset.business_criticality,
                data_classification=asset.data_classification,
                environment=asset.environment,
                internet_exposed=asset.internet_exposed,
                context_source=(contexts.get(asset_id).context_source if contexts.get(asset_id) else Provenance.INFERRED),
                open_port_count=open_port_count,
            )

            if existing is None:
                finding = _new_finding(
                    organization_id=organization_id,
                    asset=asset,
                    scan=scan,
                    rule=rule,
                    match=match,
                    assessment=assessment,
                    now=now,
                )
                session.add(finding)
                session.flush()
                result.findings_created += 1

                session.add(
                    FindingEvent(
                        organization_id=organization_id,
                        finding_id=finding.id,
                        event_type="CREATED",
                        to_value=FindingStatus.OPEN.value,
                        detail=match.summary,
                        actor_label="scanner",
                        scan_id=scan.id,
                        created_at=now,
                    )
                )
            else:
                finding = existing
                was_resolved = finding.status is FindingStatus.RESOLVED
                if was_resolved:
                    finding.status = FindingStatus.OPEN
                    finding.resolved_at = None
                    finding.reopen_count += 1
                    result.findings_reopened += 1
                    session.add(
                        FindingEvent(
                            organization_id=organization_id,
                            finding_id=finding.id,
                            event_type="REOPENED",
                            from_value=FindingStatus.RESOLVED.value,
                            to_value=FindingStatus.OPEN.value,
                            detail=(
                                "The condition was detected again by a later scan after having "
                                "been marked resolved."
                            ),
                            actor_label="scanner",
                            scan_id=scan.id,
                            created_at=now,
                        )
                    )
                else:
                    result.findings_updated += 1

                # Refresh the explanatory fields from the current detection so
                # wording improvements and new evidence propagate.
                finding.severity = match.severity or rule.severity
                finding.confidence = match.confidence or rule.default_confidence
                finding.description = match.summary or finding.description
                finding.detection_explanation = match.detection_explanation
                finding.impact = match.impact
                finding.remediation_summary = rule.remediation
                finding.risk_score = assessment.score
                finding.risk_factors = assessment.factors
                finding.risk_explanation = assessment.explanation
                finding.criticality_boost = assessment.criticality_boost
                finding.last_seen_at = now
                finding.last_scan_id = scan.id
                if match.vulnerability_refs:
                    finding.vulnerability_refs = match.vulnerability_refs

            # Replace evidence with the current detection's evidence. Old rows
            # are superseded rather than appended forever, but each row keeps
            # its own observation reference and checksum.
            for old in list(finding.evidence):
                session.delete(old)
            session.flush()

            for evidence_row in _build_evidence(
                organization_id=organization_id,
                finding=finding,
                match=match,
                observations=asset_observations,
                scan=scan,
            ):
                session.add(evidence_row)
                result.evidence_rows += 1

    # Any finding that was active but did not reproduce is resolved.
    if persist:
        result.findings_resolved = _resolve_absent_findings(
            session,
            organization_id=organization_id,
            scan=scan,
            matched_keys=matched_keys,
            asset_ids=list(by_asset.keys()),
        )

    session.flush()
    return result


def _resolve_absent_findings(
    session: Session,
    *,
    organization_id: str,
    scan: Scan,
    matched_keys: set[str],
    asset_ids: list[str],
) -> int:
    """Mark findings that did not reproduce as RESOLVED, with verification evidence.

    Only findings on assets that were actually scanned are considered. A finding
    on an asset the scan never reached must stay open, because absence of a
    scan is not absence of the problem.
    """
    now = utcnow()
    active = list(
        session.execute(
            select(Finding).where(
                Finding.organization_id == organization_id,
                Finding.asset_id.in_(asset_ids),
                Finding.status.in_([s.value for s in ACTIVE_FINDING_STATUSES]),
            )
        ).scalars()
    )

    resolved = 0
    for finding in active:
        if finding.dedup_key in matched_keys:
            continue

        finding.status = FindingStatus.RESOLVED
        finding.resolved_at = now
        finding.last_scan_id = scan.id
        resolved += 1

        session.add(
            FindingEvent(
                organization_id=organization_id,
                finding_id=finding.id,
                event_type="RESOLVED",
                from_value=FindingStatus.OPEN.value,
                to_value=FindingStatus.RESOLVED.value,
                detail=(
                    f"Scan {scan.id} covered this asset and the detection rule did not reproduce "
                    f"the condition. Veyl treats absence of reproduction in an actual scan as "
                    f"resolution; it does not assume the issue is gone if the asset was not "
                    f"scanned."
                ),
                actor_label="scanner",
                scan_id=scan.id,
                created_at=now,
            )
        )

        # Record the verification evidence on the remediation record.
        remediation = finding.remediation
        if remediation is not None:
            remediation.verified_at = now
            remediation.verified_by_scan_id = scan.id
            remediation.verification_evidence = {
                "scan_id": scan.id,
                "verified_at": now.isoformat(),
                "method": "rule_did_not_reproduce",
                "explanation": (
                    "The asset was scanned in this run, the observations the rule requires were "
                    "collected, and the rule produced no match. The absence of a match is the "
                    "evidence."
                ),
            }

    session.flush()
    return resolved
