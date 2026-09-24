"""Transparent risk model.

Every finding gets a score between 0 and 100, and — more importantly — a
:attr:`RiskAssessment.factors` dictionary listing exactly what contributed to
it and by how much. The UI renders that dictionary. A reader can therefore see
*why* something is at the top of the list without trusting the number.

The model is additive and capped. There is no machine learning and no
opaque weighting, because an unexplainable priority score is worse than no score
at all: it cannot be argued with, cannot be tuned by the customer, and gives a
false impression of precision.

Factors, in order of weight:

===========================  =====  ===========================================
Factor                       Max    Rationale
===========================  =====  ===========================================
base severity                40     the rule's assessment of the class of issue
internet exposure            15     reachable from outside is categorically worse
business criticality         15     read from the asset, provenance is recorded
data classification          10     sensitive data raises consequence
confidence                    8     a low-confidence finding should not top a list
vulnerability evidence        7     only when a version-matched CVE exists
environment                   3     production carries more operational weight
service class                 2     control-plane and data stores rank above the rest
===========================  =====  ===========================================

Base severity alone tops out at 40, which is deliberate: severity can never
dominate the list on its own. An INFO finding on a critical, internet-exposed,
sensitive-data production asset scores higher than a HIGH finding on an
unclassified internal host, and that is the correct ordering for this product.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from veyl_api.enums import (
    CONFIDENCE_ORDER,
    CRITICALITY_ORDER,
    DATA_CLASSIFICATION_ORDER,
    SEVERITY_ORDER,
    BusinessCriticality,
    Confidence,
    DataClassification,
    Environment,
    Provenance,
    Severity,
)
from veyl_api.models import Asset
from veyl_rules.framework import RuleDefinition, RuleMatch

MAX_SCORE = 100.0

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 4.0,
    Severity.LOW: 12.0,
    Severity.MEDIUM: 24.0,
    Severity.HIGH: 34.0,
    Severity.CRITICAL: 40.0,
}

CONFIDENCE_WEIGHTS: dict[Confidence, float] = {
    Confidence.LOW: 0.0,
    Confidence.MEDIUM: 4.0,
    Confidence.HIGH: 8.0,
}

CRITICALITY_WEIGHTS: dict[BusinessCriticality, float] = {
    BusinessCriticality.LOW: 0.0,
    BusinessCriticality.MEDIUM: 5.0,
    BusinessCriticality.HIGH: 10.0,
    BusinessCriticality.CRITICAL: 15.0,
}

DATA_CLASSIFICATION_WEIGHTS: dict[DataClassification, float] = {
    DataClassification.PUBLIC: 0.0,
    DataClassification.INTERNAL: 3.0,
    DataClassification.CONFIDENTIAL: 7.0,
    DataClassification.SENSITIVE: 10.0,
}

ENVIRONMENT_WEIGHTS: dict[Environment, float] = {
    Environment.PRODUCTION: 3.0,
    Environment.STAGING: 1.5,
    Environment.DEVELOPMENT: 0.5,
    Environment.INTERNAL: 1.0,
    Environment.UNKNOWN: 0.0,
}


@dataclass
class RiskAssessment:
    """The score, the factors behind it, and a plain-language explanation."""

    score: float
    factors: dict[str, Any] = field(default_factory=dict)
    explanation: str = ""
    #: How much of the score came from business context specifically.
    criticality_boost: float = 0.0

    #: Priority band derived from the score, used for default assignment.
    @property
    def priority(self) -> str:
        if self.score >= 75:
            return "URGENT"
        if self.score >= 55:
            return "HIGH"
        if self.score >= 35:
            return "MEDIUM"
        return "LOW"

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "priority": self.priority,
            "factors": self.factors,
            "explanation": self.explanation,
            "criticality_boost": self.criticality_boost,
        }


def assess_risk(
    *,
    rule: RuleDefinition,
    match: RuleMatch,
    asset: Asset,
    business_criticality: BusinessCriticality,
    data_classification: DataClassification,
    environment: Environment,
    internet_exposed: bool,
    context_source: Provenance | None = None,
    open_port_count: int = 0,
) -> RiskAssessment:
    """Score one finding and record every contributing factor."""
    severity = match.severity or rule.severity
    confidence = match.confidence or rule.default_confidence

    factors: dict[str, Any] = {}

    base = SEVERITY_WEIGHTS.get(severity, 0.0)
    factors["base_severity"] = {
        "value": severity.value,
        "contribution": base,
        "max": 40.0,
        "explanation": f"The detection rule rates this class of issue {severity.value}.",
    }

    exposure = 15.0 if internet_exposed else 0.0
    factors["internet_exposure"] = {
        "value": internet_exposed,
        "contribution": exposure,
        "max": 15.0,
        "explanation": (
            "The asset is reachable from the assessed network position, so the condition is "
            "reachable by whoever else can reach it."
            if internet_exposed
            else "The asset was not observed as reachable, which limits who can act on this."
        ),
    }

    criticality = CRITICALITY_WEIGHTS.get(business_criticality, 0.0)
    factors["business_criticality"] = {
        "value": business_criticality.value,
        "contribution": criticality,
        "max": 15.0,
        "provenance": context_source.value if context_source else "UNKNOWN",
        "explanation": (
            f"The asset is classified {business_criticality.value} business criticality"
            + (
                f" (source: {context_source.value}), so the consequence of this condition falls "
                f"on a system the organization has identified as important."
                if business_criticality in (BusinessCriticality.HIGH, BusinessCriticality.CRITICAL)
                else ", which does not raise the priority of this finding."
            )
        ),
    }

    data = DATA_CLASSIFICATION_WEIGHTS.get(data_classification, 0.0)
    factors["data_classification"] = {
        "value": data_classification.value,
        "contribution": data,
        "max": 10.0,
        "provenance": context_source.value if context_source else "UNKNOWN",
        "explanation": (
            f"The asset carries a data classification of {data_classification.value}"
            + (
                ", which raises the consequence of any disclosure."
                if data_classification in (DataClassification.CONFIDENTIAL, DataClassification.SENSITIVE)
                else ", which does not raise the consequence of this finding."
            )
        ),
    }

    conf = CONFIDENCE_WEIGHTS.get(confidence, 0.0)
    factors["detection_confidence"] = {
        "value": confidence.value,
        "contribution": conf,
        "max": 8.0,
        "explanation": (
            f"Veyl has {confidence.value} confidence in this detection, based on the quality of "
            f"the underlying evidence. A low-confidence finding is ranked below a well-evidenced "
            f"one of the same class."
        ),
    }

    cve_contribution = 0.0
    version_matched = [
        ref
        for ref in match.vulnerability_refs
        if ref.get("status") in ("CONFIRMED_AFFECTED", "POTENTIALLY_AFFECTED")
        and ref.get("version_evidence")
    ]
    if version_matched:
        cve_contribution = 7.0
    factors["known_vulnerability"] = {
        "value": len(version_matched),
        "contribution": cve_contribution,
        "max": 7.0,
        "explanation": (
            f"{len(version_matched)} vulnerability record(s) were matched against a specific "
            f"observed product version. Veyl does not add weight for a CVE that only shares a "
            f"product name."
            if version_matched
            else "No version-matched vulnerability record was available, so no weight is added."
        ),
    }

    env = ENVIRONMENT_WEIGHTS.get(environment, 0.0)
    factors["environment"] = {
        "value": environment.value,
        "contribution": env,
        "max": 3.0,
        "explanation": f"The asset is classified as {environment.value}.",
    }

    service_class = match.risk_factors.get("service_class")
    service_contribution = 0.0
    if service_class in ("administrative", "database"):
        service_contribution = 2.0
    factors["service_class"] = {
        "value": service_class or "general",
        "contribution": service_contribution,
        "max": 2.0,
        "explanation": (
            "The finding concerns a control-plane or data-store service, which carries a higher "
            "consequence per successful access than a general application service."
            if service_contribution
            else "The finding does not concern a control-plane or data-store service."
        ),
    }

    raw = (
        base + exposure + criticality + data + conf + cve_contribution + env + service_contribution
    )
    score = round(min(raw, MAX_SCORE), 1)

    criticality_boost = round(criticality + data, 1)

    explanation = _explain(
        severity=severity,
        confidence=confidence,
        score=score,
        internet_exposed=internet_exposed,
        business_criticality=business_criticality,
        data_classification=data_classification,
        has_version_matched_cve=bool(version_matched),
        context_source=context_source,
    )

    factors["_summary"] = {
        "raw_total": round(raw, 1),
        "capped_at": MAX_SCORE,
        "final_score": score,
        "priority": (
            "URGENT" if score >= 75 else "HIGH" if score >= 55 else "MEDIUM" if score >= 35 else "LOW"
        ),
    }

    return RiskAssessment(
        score=score,
        factors=factors,
        explanation=explanation,
        criticality_boost=criticality_boost,
    )


def _criticality_phrase(criticality: BusinessCriticality) -> str:
    """Render criticality as a phrase that reads naturally inside a sentence."""
    return {
        BusinessCriticality.CRITICAL: "business-critical",
        BusinessCriticality.HIGH: "high-criticality",
        BusinessCriticality.MEDIUM: "medium-criticality",
        BusinessCriticality.LOW: "low-criticality",
    }[criticality]


def _explain(
    *,
    severity: Severity,
    confidence: Confidence,
    score: float,
    internet_exposed: bool,
    business_criticality: BusinessCriticality,
    data_classification: DataClassification,
    has_version_matched_cve: bool,
    context_source: Provenance | None,
) -> str:
    """Build the sentence shown to the reader explaining the priority."""
    parts: list[str] = []

    if (
        internet_exposed
        and business_criticality in (BusinessCriticality.HIGH, BusinessCriticality.CRITICAL)
    ):
        parts.append(
            f"This finding is prioritized because a "
            f"{_criticality_phrase(business_criticality)} asset is externally reachable"
        )
    elif internet_exposed:
        parts.append("This finding is prioritized because the asset is externally reachable")
    elif business_criticality in (BusinessCriticality.HIGH, BusinessCriticality.CRITICAL):
        parts.append(
            f"This finding is prioritized because the asset is {_criticality_phrase(business_criticality)}, "
            f"although it was not observed as externally reachable"
        )
    else:
        parts.append(
            "This finding is ranked primarily on the class of issue it represents, because the "
            "asset is neither externally reachable nor classified as critical"
        )

    if has_version_matched_cve:
        parts.append(
            "the asset runs a component that matches a known vulnerability by product and version"
        )

    if data_classification in (DataClassification.CONFIDENTIAL, DataClassification.SENSITIVE):
        parts.append(
            f"it carries {data_classification.value.lower()} data, which raises the consequence "
            f"of disclosure"
        )

    sentence = parts[0]
    if len(parts) > 1:
        sentence += ", and " + "; ".join(parts[1:])
    sentence += "."

    if context_source is Provenance.USER_PROVIDED:
        sentence += (
            " The business classification used here was provided by your organization, not "
            "inferred by Veyl."
        )
    elif context_source is Provenance.INFERRED:
        sentence += (
            " The business classification used here was inferred and has not been confirmed by "
            "your organization, so it may understate the true priority."
        )

    if confidence is Confidence.LOW:
        sentence += (
            " Detection confidence is LOW, so Veyl has deliberately ranked this below findings "
            "of the same class that rest on stronger evidence."
        )

    sentence += f" Composite score {score} of 100."
    return sentence


def default_priority_for(score: float) -> str:
    """Map a score to the default remediation priority."""
    if score >= 75:
        return "URGENT"
    if score >= 55:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"
