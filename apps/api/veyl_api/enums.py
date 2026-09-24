"""Enumerations shared across persistence, rules, and the API surface.

These are deliberately plain ``str`` enums so they round-trip through JSON,
SQL, and rule definitions without conversion layers.
"""

from __future__ import annotations

from enum import StrEnum


class OrganizationRole(StrEnum):
    """Roles a user can hold inside an organization."""

    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    ENGINEER = "ENGINEER"
    EXECUTIVE = "EXECUTIVE"


#: Capabilities granted per role. Authorization is *always* checked server-side
#: against this table; the frontend only uses it to hide controls.
ROLE_CAPABILITIES: dict[OrganizationRole, frozenset[str]] = {
    OrganizationRole.ADMIN: frozenset(
        {
            "org:read",
            "org:write",
            "member:read",
            "member:write",
            "scope:read",
            "scope:write",
            "asset:read",
            "asset:write",
            "scan:read",
            "scan:create",
            "finding:read",
            "finding:write",
            "remediation:write",
            "report:read",
            "report:generate",
            "audit:read",
            "graph:read",
            "rule:read",
        }
    ),
    OrganizationRole.SECURITY_ANALYST: frozenset(
        {
            "org:read",
            "member:read",
            "scope:read",
            "scope:write",
            "asset:read",
            "asset:write",
            "scan:read",
            "scan:create",
            "finding:read",
            "finding:write",
            "remediation:write",
            "report:read",
            "report:generate",
            "audit:read",
            "graph:read",
            "rule:read",
        }
    ),
    OrganizationRole.ENGINEER: frozenset(
        {
            "org:read",
            "scope:read",
            "asset:read",
            "scan:read",
            "scan:create",
            "finding:read",
            "remediation:write",
            "report:read",
            "graph:read",
            "rule:read",
        }
    ),
    OrganizationRole.EXECUTIVE: frozenset(
        {
            "org:read",
            "asset:read",
            "finding:read",
            "report:read",
            "report:generate",
            "graph:read",
        }
    ),
}


class AssetType(StrEnum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    SERVER = "SERVER"
    APPLICATION = "APPLICATION"
    API = "API"
    DATABASE = "DATABASE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    SERVICE = "SERVICE"
    OTHER = "OTHER"


class Environment(StrEnum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    INTERNAL = "INTERNAL"
    UNKNOWN = "UNKNOWN"


class AssetStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    RETIRED = "RETIRED"


class BusinessCriticality(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DataClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SENSITIVE = "SENSITIVE"


class BusinessFunction(StrEnum):
    PAYMENTS = "PAYMENTS"
    AUTHENTICATION = "AUTHENTICATION"
    CUSTOMER_PORTAL = "CUSTOMER_PORTAL"
    INTERNAL = "INTERNAL"
    MARKETING = "MARKETING"
    DEVELOPMENT = "DEVELOPMENT"
    OTHER = "OTHER"


class AssetOwner(StrEnum):
    SECURITY_TEAM = "SECURITY_TEAM"
    ENGINEERING = "ENGINEERING"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    PLATFORM = "PLATFORM"
    DATA = "DATA"
    UNASSIGNED = "UNASSIGNED"


class AuthorizationStatus(StrEnum):
    """Whether the organization has attested permission to assess a target."""

    AUTHORIZED = "AUTHORIZED"
    PENDING = "PENDING"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class Provenance(StrEnum):
    """Where a piece of data came from.

    Veyl must never blur the line between something it measured and something a
    human told it. Every attribute carries one of these.
    """

    OBSERVED = "OBSERVED"  # Veyl directly measured it
    INFERRED = "INFERRED"  # derived by deterministic logic from observations
    USER_PROVIDED = "USER_PROVIDED"  # a human entered or confirmed it


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}

CRITICALITY_ORDER: dict[BusinessCriticality, int] = {
    BusinessCriticality.LOW: 0,
    BusinessCriticality.MEDIUM: 1,
    BusinessCriticality.HIGH: 2,
    BusinessCriticality.CRITICAL: 3,
}

DATA_CLASSIFICATION_ORDER: dict[DataClassification, int] = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.SENSITIVE: 3,
}


class RuleCategory(StrEnum):
    NETWORK = "network"
    WEB = "web"
    API = "api"
    TLS = "tls"
    AUTHENTICATION = "authentication"
    INFRASTRUCTURE = "infrastructure"
    EXPOSURE = "exposure"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


#: Statuses that count as "still needs attention".
ACTIVE_FINDING_STATUSES: frozenset[FindingStatus] = frozenset(
    {FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED, FindingStatus.IN_PROGRESS}
)


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanTrigger(StrEnum):
    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"
    API = "API"
    DEMO = "DEMO"


class ChangeType(StrEnum):
    """Every observable difference between two scans of the same scope."""

    ASSET_ADDED = "ASSET_ADDED"
    ASSET_REMOVED = "ASSET_REMOVED"
    PORT_OPENED = "PORT_OPENED"
    PORT_CLOSED = "PORT_CLOSED"
    SERVICE_CHANGED = "SERVICE_CHANGED"
    SERVICE_VERSION_CHANGED = "SERVICE_VERSION_CHANGED"
    CERTIFICATE_CHANGED = "CERTIFICATE_CHANGED"
    CERTIFICATE_EXPIRING = "CERTIFICATE_EXPIRING"
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    DNS_CHANGED = "DNS_CHANGED"
    HTTP_STATUS_CHANGED = "HTTP_STATUS_CHANGED"
    SECURITY_HEADER_CHANGED = "SECURITY_HEADER_CHANGED"
    AUTHENTICATION_CHANGED = "AUTHENTICATION_CHANGED"
    FINDING_ADDED = "FINDING_ADDED"
    FINDING_RESOLVED = "FINDING_RESOLVED"
    FINDING_REOPENED = "FINDING_REOPENED"
    TECH_ADDED = "TECH_ADDED"
    TECH_REMOVED = "TECH_REMOVED"


#: Change types that represent newly introduced risk (used for "New Exposures").
RISK_INCREASING_CHANGES: frozenset[ChangeType] = frozenset(
    {
        ChangeType.ASSET_ADDED,
        ChangeType.PORT_OPENED,
        ChangeType.SERVICE_CHANGED,
        ChangeType.SERVICE_VERSION_CHANGED,
        ChangeType.CERTIFICATE_EXPIRED,
        ChangeType.AUTHENTICATION_CHANGED,
        ChangeType.FINDING_ADDED,
        ChangeType.FINDING_REOPENED,
        ChangeType.TECH_ADDED,
        ChangeType.HTTP_STATUS_CHANGED,
    }
)


class ChangeSignificance(StrEnum):
    INFORMATIONAL = "INFORMATIONAL"
    NOTABLE = "NOTABLE"
    SIGNIFICANT = "SIGNIFICANT"
    CRITICAL = "CRITICAL"


class NodeType(StrEnum):
    ORGANIZATION = "Organization"
    ASSET = "Asset"
    DOMAIN = "Domain"
    IP = "IP"
    PORT = "Port"
    SERVICE = "Service"
    APPLICATION = "Application"
    API = "API"
    ENDPOINT = "Endpoint"
    FINDING = "Finding"
    CERTIFICATE = "Certificate"
    BUSINESS_FUNCTION = "BusinessFunction"


class EdgeType(StrEnum):
    OWNS = "OWNS"
    RESOLVES_TO = "RESOLVES_TO"
    EXPOSES = "EXPOSES"
    RUNS = "RUNS"
    SERVES = "SERVES"
    CONNECTS_TO = "CONNECTS_TO"
    DEPENDS_ON = "DEPENDS_ON"
    AFFECTED_BY = "AFFECTED_BY"
    BELONGS_TO = "BELONGS_TO"
    CHANGED_TO = "CHANGED_TO"


class AttackPathState(StrEnum):
    """How strongly Veyl is willing to assert a path.

    Veyl never claims a confirmed compromise. ``VERIFIED`` is reserved for paths
    where an authorized, non-destructive check produced positive evidence.
    """

    POTENTIAL = "POTENTIAL"
    LIKELY = "LIKELY"
    VERIFIED = "VERIFIED"
    RULED_OUT = "RULED_OUT"


class VulnerabilityStatus(StrEnum):
    """Deliberately distinguishes speculation from evidence."""

    POTENTIALLY_AFFECTED = "POTENTIALLY_AFFECTED"
    CONFIRMED_AFFECTED = "CONFIRMED_AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"


class ReportKind(StrEnum):
    EXECUTIVE = "EXECUTIVE"
    TECHNICAL = "TECHNICAL"


class ReportFormat(StrEnum):
    HTML = "HTML"
    JSON = "JSON"
    PDF = "PDF"


class ReportStatus(StrEnum):
    PENDING = "PENDING"
    READY = "READY"
    FAILED = "FAILED"


class AuditAction(StrEnum):
    LOGIN = "LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    USER_CREATED = "USER_CREATED"
    MEMBER_ADDED = "MEMBER_ADDED"
    MEMBER_UPDATED = "MEMBER_UPDATED"
    MEMBER_REMOVED = "MEMBER_REMOVED"
    MEMBER_ROLE_CHANGED = "MEMBER_ROLE_CHANGED"
    ORGANIZATION_CREATED = "ORGANIZATION_CREATED"
    ORGANIZATION_UPDATED = "ORGANIZATION_UPDATED"
    SCOPE_CREATED = "SCOPE_CREATED"
    SCOPE_UPDATED = "SCOPE_UPDATED"
    SCOPE_DELETED = "SCOPE_DELETED"
    SCOPE_AUTHORIZATION_CHANGED = "SCOPE_AUTHORIZATION_CHANGED"
    SCAN_CREATED = "SCAN_CREATED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    SCAN_BLOCKED = "SCAN_BLOCKED"
    ASSET_UPDATED = "ASSET_UPDATED"
    ASSET_CONTEXT_UPDATED = "ASSET_CONTEXT_UPDATED"
    FINDING_UPDATED = "FINDING_UPDATED"
    FINDING_ASSIGNED = "FINDING_ASSIGNED"
    FINDING_STATUS_CHANGED = "FINDING_STATUS_CHANGED"
    FINDING_RESCORED = "FINDING_RESCORED"
    REMEDIATION_NOTE_ADDED = "REMEDIATION_NOTE_ADDED"
    REMEDIATION_UPDATED = "REMEDIATION_UPDATED"
    REMEDIATION_VERIFIED = "REMEDIATION_VERIFIED"
    CHANGE_ACKNOWLEDGED = "CHANGE_ACKNOWLEDGED"
    GRAPH_REBUILT = "GRAPH_REBUILT"
    ATTACK_PATHS_RECOMPUTED = "ATTACK_PATHS_RECOMPUTED"
    REPORT_GENERATED = "REPORT_GENERATED"
    RULE_EVALUATED = "RULE_EVALUATED"
