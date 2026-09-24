"""Exposure-class rules.

These rules ask questions that only exist because Veyl keeps history: is this
exposure new, did it come back after being fixed, and does the business context
mean the usual severity is wrong?

A rule in this package may read the *current* asset state and its business
context. It may not read another tenant, and it may not invent a change — changes
come from the deterministic diff in :mod:`veyl_correlation.changes`, and these
rules consume the change records the evaluator hands them.
"""

from __future__ import annotations

from veyl_api.enums import Confidence, RuleCategory, Severity
from veyl_rules.framework import RuleContext, RuleDefinition, RuleMatch


def _open_ports(context: RuleContext) -> list[int]:
    scan = context.first("port_scan")
    if not scan:
        return []
    return sorted(int(p) for p in scan.get("open_ports", []) if str(p).isdigit())


def check_critical_asset_internet_exposed(context: RuleContext) -> list[RuleMatch]:
    """A business-critical asset is reachable from the assessed position.

    This rule exists to answer the question the executive dashboard asks: what
    matters? It does not restate a technical finding. It records that an asset
    the organization has itself labelled critical is exposed, and it names the
    classification so the reader can see where the judgement came from.
    """
    if context.business_criticality not in ("HIGH", "CRITICAL"):
        return []
    if not context.internet_exposed:
        return []

    ports = _open_ports(context)
    asset_context = context.first("business_context") or {}

    severity = Severity.CRITICAL if context.business_criticality == "CRITICAL" else Severity.HIGH
    classification_note = (
        "Veyl did not determine this criticality. The classification was set on the asset by the "
        f"organization (source: {asset_context.get('context_source', 'UNKNOWN')}). Veyl is "
        "reporting the exposure against the business context it was given."
    )

    return [
        RuleMatch(
            subject_suffix="critical-exposed",
            summary=(
                f"{context.business_criticality} business-critical asset is reachable on "
                f"{len(ports)} port(s)"
            ),
            detection_explanation=(
                f"The port sweep found this asset reachable with {len(ports)} open port(s): "
                f"{', '.join(str(p) for p in ports[:20]) or 'none'}. The asset is classified "
                f"{context.business_criticality} criticality, "
                f"{context.data_classification} data classification, function "
                f"{context.business_function}, environment {context.environment}. "
                + classification_note
            ),
            impact=(
                f"Reachability of a {context.business_criticality.lower()}-criticality asset means "
                f"any weakness in the services it runs is reachable from the assessed position, "
                f"and the consequence of a compromise falls on a system the organization has "
                f"identified as important rather than on a peripheral one. This finding is about "
                f"where the risk lands, not about a specific technical defect: the specific "
                f"defects, if any, are listed as their own findings on this asset."
            ),
            evidence=[
                {
                    "kind": "port_scan",
                    "matcher": "open_ports non-empty and business_criticality in {HIGH, CRITICAL}",
                    "detail": {
                        "open_ports": ports,
                        "internet_exposed": context.internet_exposed,
                        "business_criticality": context.business_criticality,
                        "data_classification": context.data_classification,
                        "business_function": context.business_function,
                        "environment": context.environment,
                        "classification_source": asset_context.get("context_source", "UNKNOWN"),
                    },
                }
            ],
            severity=severity,
            confidence=Confidence.HIGH,
            risk_factors={
                "exposure_class": "business_critical",
                "business_criticality": context.business_criticality,
                "data_classification": context.data_classification,
                "open_port_count": len(ports),
            },
        )
    ]


def check_production_service_on_nonstandard_port(context: RuleContext) -> list[RuleMatch]:
    """A production asset publishes a service on a high, non-standard port."""
    if context.environment != "PRODUCTION":
        return []

    standard = {22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432}
    unusual = [p for p in _open_ports(context) if p > 1024 and p not in standard]
    if not unusual:
        return []

    services = {
        str(o.get("port")): o for o in context.of_kind("service_fingerprint")
    }
    described = [
        f"{p} ({(services.get(str(p)) or {}).get('service_name', 'unknown')})" for p in unusual
    ]

    return [
        RuleMatch(
            subject_suffix="nonstandard-ports",
            summary=f"Production asset exposes {len(unusual)} service(s) on non-standard ports",
            detection_explanation=(
                f"The asset is classified as PRODUCTION and the port sweep found listener(s) on "
                f"{', '.join(described)}. These are above 1024 and outside the conventional "
                f"service port set, so they do not correspond to a well-known protocol."
            ),
            impact=(
                "Services on non-standard ports are less likely to be covered by egress and "
                "ingress rules written against conventional ports, and they are frequently "
                "forgotten when the intent was to publish something on a temporary basis. In a "
                "production environment this is worth confirming rather than assuming."
            ),
            evidence=[
                {
                    "kind": "port_scan",
                    "matcher": "environment == PRODUCTION and open port > 1024 outside standard set",
                    "detail": {
                        "environment": context.environment,
                        "nonstandard_ports": unusual,
                        "all_open_ports": _open_ports(context),
                    },
                }
            ],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            risk_factors={
                "exposure_class": "unexpected_production_exposure",
                "environment": context.environment,
            },
        )
    ]


def check_development_asset_in_production_scope(context: RuleContext) -> list[RuleMatch]:
    """A non-production asset is reachable the same way production is."""
    if context.environment not in ("DEVELOPMENT", "STAGING"):
        return []
    if not context.internet_exposed:
        return []

    ports = _open_ports(context)
    return [
        RuleMatch(
            subject_suffix="nonprod-exposed",
            summary=(
                f"{context.environment.title()} asset is reachable with {len(ports)} open "
                f"port(s)"
            ),
            detection_explanation=(
                f"This asset is classified {context.environment} and the port sweep found "
                f"{len(ports)} open port(s): {', '.join(str(p) for p in ports[:20])}. Veyl "
                f"records the environment classification from the scope registry and the "
                f"hostname convention; it did not verify the classification itself."
            ),
            impact=(
                "Development and staging environments are held to lower operational standards "
                "than production: they are updated less often, they more frequently carry debug "
                "configuration and default credentials, and they are commonly built from a copy "
                "of production data. The same reachability carries more risk on such a host than "
                "it would on a hardened production one, and a compromise there is frequently a "
                "route into production through shared credentials or network trust."
            ),
            evidence=[
                {
                    "kind": "port_scan",
                    "matcher": "environment in {DEVELOPMENT, STAGING} and internet_exposed",
                    "detail": {
                        "environment": context.environment,
                        "open_ports": ports,
                        "internet_exposed": context.internet_exposed,
                    },
                }
            ],
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            risk_factors={
                "exposure_class": "nonproduction_exposed",
                "environment": context.environment,
            },
        )
    ]


def check_sensitive_data_asset_exposed(context: RuleContext) -> list[RuleMatch]:
    """An asset holding sensitive data is reachable."""
    if context.data_classification not in ("CONFIDENTIAL", "SENSITIVE"):
        return []
    if not context.internet_exposed:
        return []

    return [
        RuleMatch(
            subject_suffix="sensitive-data-exposed",
            summary=(
                f"Asset classified {context.data_classification} data is reachable "
                f"({len(_open_ports(context))} open port(s))"
            ),
            detection_explanation=(
                f"This asset carries a data classification of {context.data_classification}, set "
                f"by the organization, and the port sweep found it reachable with "
                f"{len(_open_ports(context))} open port(s)."
            ),
            impact=(
                f"Where an asset holds {context.data_classification.lower()} data, a compromise "
                f"carries a disclosure obligation and a regulatory dimension that a peripheral "
                f"asset does not. This affects the response to any other finding on this asset "
                f"more than it constitutes a finding of its own."
            ),
            evidence=[
                {
                    "kind": "port_scan",
                    "matcher": "data_classification in {CONFIDENTIAL, SENSITIVE} and internet_exposed",
                    "detail": {
                        "data_classification": context.data_classification,
                        "business_criticality": context.business_criticality,
                        "open_ports": _open_ports(context),
                    },
                }
            ],
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            risk_factors={
                "exposure_class": "sensitive_data",
                "data_classification": context.data_classification,
            },
        )
    ]


EXPOSURE_RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="VEYL-EXP-001",
        title="Business-critical asset is internet-reachable",
        category=RuleCategory.EXPOSURE,
        severity=Severity.CRITICAL,
        default_confidence=Confidence.HIGH,
        description=(
            "An asset the organization has classified HIGH or CRITICAL criticality is reachable "
            "from the assessed position."
        ),
        detection=(
            "Fires when the asset's business relevance classification is HIGH or CRITICAL and "
            "the port sweep found at least one open port. The classification is read from the "
            "asset context and its provenance is stated in the finding."
        ),
        evidence_requirements=["port_scan", "business_context"],
        remediation=(
            "Treat every other finding on this asset as high priority and confirm that each "
            "exposed service is intended to be reachable. Where the classification is wrong, "
            "correct it, because this rule and the risk model both act on it."
        ),
        check=check_critical_asset_internet_exposed,
        requires=["port_scan", "business_context"],
    ),
    RuleDefinition(
        rule_id="VEYL-EXP-002",
        title="Production asset exposes non-standard ports",
        category=RuleCategory.EXPOSURE,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description=(
            "A production asset has listeners on high ports that do not correspond to a "
            "conventional protocol."
        ),
        detection=(
            "Fires when the asset environment is PRODUCTION and at least one open port is above "
            "1024 and outside the conventional service port set."
        ),
        evidence_requirements=["port_scan"],
        remediation=(
            "Confirm each non-standard listener is intended and documented. Where it is not, "
            "remove the listener or restrict its reachability."
        ),
        check=check_production_service_on_nonstandard_port,
        requires=["port_scan", "business_context"],
    ),
    RuleDefinition(
        rule_id="VEYL-EXP-003",
        title="Non-production asset exposed to the internet",
        category=RuleCategory.EXPOSURE,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.MEDIUM,
        description="A staging or development asset is reachable from the assessed position.",
        detection=(
            "Fires when the asset environment is STAGING or DEVELOPMENT and the port sweep found "
            "at least one open port."
        ),
        evidence_requirements=["port_scan", "business_context"],
        remediation=(
            "Confirm the exposure is intended. If the environment is genuinely temporary, "
            "schedule its removal; the common failure mode is that a temporary staging system "
            "becomes permanent and is never re-reviewed."
        ),
        check=check_development_asset_in_production_scope,
        requires=["port_scan", "business_context"],
    ),
    RuleDefinition(
        rule_id="VEYL-EXP-004",
        title="Asset holding sensitive data is exposed",
        category=RuleCategory.EXPOSURE,
        severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        description=(
            "An asset classified CONFIDENTIAL or SENSITIVE is reachable from the assessed "
            "position."
        ),
        detection=(
            "Fires when the asset data classification is CONFIDENTIAL or SENSITIVE and the port "
            "sweep found at least one open port."
        ),
        evidence_requirements=["port_scan", "business_context"],
        remediation=(
            "Confirm the exposure is required and that the services on the asset enforce "
            "authentication and encryption. Review whether the data classification is current."
        ),
        check=check_sensitive_data_asset_exposed,
        requires=["port_scan", "business_context"],
    ),
]
