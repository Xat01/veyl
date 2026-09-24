"""Pydantic schemas for the Veyl HTTP API.

Two rules govern everything in this module:

* **Responses never leak internal structure.** A schema is an explicit contract,
  not a serialised ORM object. Fields are added deliberately, so a new column
  cannot accidentally become part of the public API.
* **Provenance travels with the data.** Any value Veyl did not measure is
  labelled with where it came from. A consumer of this API can always tell the
  difference between something observed and something asserted, because the
  field that says so is never optional.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from veyl_api.enums import (
    AssetOwner,
    AssetStatus,
    AssetType,
    AttackPathState,
    AuthorizationStatus,
    BusinessCriticality,
    BusinessFunction,
    ChangeSignificance,
    ChangeType,
    Confidence,
    DataClassification,
    Environment,
    FindingStatus,
    OrganizationRole,
    Provenance,
    ReportFormat,
    ReportKind,
    ReportStatus,
    ScanStatus,
    ScanTrigger,
    Severity,
)

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class APIModel(BaseModel):
    """Common configuration for every schema in the API."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class Page(APIModel):
    """Pagination envelope."""

    total: int = Field(description="Total matching rows, ignoring pagination.")
    limit: int
    offset: int
    items: list[Any] = Field(default_factory=list, description="Page of results.")


# ---------------------------------------------------------------------------
# Auth and organization
# ---------------------------------------------------------------------------


class LoginRequest(APIModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)
    organization_slug: str | None = Field(
        default=None,
        max_length=100,
        description="Required only when the user belongs to more than one organization.",
    )


class TokenResponse(APIModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(description="Access-token lifetime in seconds.")


class RefreshRequest(APIModel):
    refresh_token: str = Field(min_length=10)


class OrganizationSummary(APIModel):
    id: str
    name: str
    slug: str
    role: OrganizationRole


class MemberSummary(APIModel):
    id: str
    user_id: str
    email: str
    full_name: str
    role: OrganizationRole
    is_active: bool
    created_at: datetime


class MemberCreate(APIModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=256)
    full_name: str = Field(min_length=1, max_length=200)
    role: OrganizationRole = OrganizationRole.ENGINEER

    @field_validator("password")
    @classmethod
    def _check_strength(cls, value: str) -> str:
        # Import here: the strength policy lives with the password hashing so
        # there is exactly one definition of "strong enough".
        from veyl_api.security.auth import validate_password_strength

        problems = validate_password_strength(value)
        if problems:
            raise ValueError("password is too weak: " + "; ".join(problems))
        return value


class MemberUpdate(APIModel):
    role: OrganizationRole | None = None
    is_active: bool | None = None


class CurrentUser(APIModel):
    id: str
    email: str
    full_name: str
    organizations: list[OrganizationSummary]
    active_organization_id: str | None = None
    role: OrganizationRole | None = None
    capabilities: list[str] = Field(
        default_factory=list,
        description="Server-computed permissions for the caller's role in the active organization.",
    )
    last_login_at: datetime | None = None


# ---------------------------------------------------------------------------
# Scope registry
# ---------------------------------------------------------------------------


class ScopeEntryCreate(APIModel):
    domain: str = Field(min_length=1, max_length=255)
    cidr: str | None = Field(default=None, max_length=64)
    environment: Environment = Environment.UNKNOWN
    asset_owner: AssetOwner = AssetOwner.UNASSIGNED
    authorization_status: AuthorizationStatus = AuthorizationStatus.PENDING
    authorized_by: str | None = Field(default=None, max_length=200)
    expires_at: datetime | None = None
    notes: str | None = Field(default=None, max_length=4000)
    is_active: bool = True
    allow_port_override: bool = Field(
        default=False,
        description="Explicitly permits this target to be scanned on ports outside the default safe set.",
    )

    @field_validator("domain")
    @classmethod
    def _reject_scheme_and_path(cls, value: str) -> str:
        # A scope entry is a host or a CIDR, never a URL. Accepting
        # "https://x.example/path" would create an entry that can never match.
        cleaned = value.strip()
        if "://" in cleaned or "/" in cleaned.rstrip("/"):
            raise ValueError(
                "domain must be a bare hostname or wildcard (e.g. 'api.example.com' or "
                "'*.example.com'), not a URL or a path"
            )
        return cleaned


class ScopeEntryUpdate(APIModel):
    environment: Environment | None = None
    asset_owner: AssetOwner | None = None
    authorization_status: AuthorizationStatus | None = None
    authorized_by: str | None = Field(default=None, max_length=200)
    expires_at: datetime | None = None
    notes: str | None = Field(default=None, max_length=4000)
    is_active: bool | None = None
    allow_port_override: bool | None = None


class ScopeEntryOut(APIModel):
    id: str
    domain: str
    cidr: str | None
    environment: Environment
    asset_owner: AssetOwner
    authorization_status: AuthorizationStatus
    authorized_by: str | None
    authorized_at: datetime | None
    expires_at: datetime | None
    notes: str | None
    is_active: bool
    allow_port_override: bool
    is_authorized_now: bool = Field(
        description="True when active, authorized, and unexpired — i.e. Veyl will scan it."
    )
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


class ScanCreate(APIModel):
    label: str | None = Field(default=None, max_length=200)
    scope_entry_ids: list[str] | None = Field(
        default=None,
        description="Specific scope entries to assess. Omit to assess every currently authorized entry.",
    )
    port_override: list[int] | None = Field(
        default=None,
        description=(
            "Ports to scan instead of the default safe set. Only honored for scope entries "
            "that explicitly allow it; otherwise the request is refused."
        ),
    )
    trigger: ScanTrigger = ScanTrigger.MANUAL

    @field_validator("port_override")
    @classmethod
    def _validate_ports(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return None
        if not value:
            raise ValueError("port_override, when supplied, must not be empty")
        if len(value) > 1024:
            raise ValueError("port_override accepts at most 1024 ports per request")
        for port in value:
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ValueError(f"invalid port: {port!r}; must be an integer in 1..65535")
        return sorted(set(value))


class ScanOut(APIModel):
    id: str
    status: ScanStatus
    trigger: ScanTrigger
    label: str | None
    started_at: datetime
    finished_at: datetime | None
    ports_scanned: int
    scanner_backend: str
    targets_requested: int
    targets_scanned: int
    targets_blocked: int
    assets_found: int
    services_found: int
    findings_created: int
    changes_detected: int
    error_message: str | None
    blocked_targets: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Targets the safety floor or scope guard refused, each with an explicit reason.",
    )
    created_at: datetime


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


class ServiceFingerprintEvidence(APIModel):
    """One piece of evidence behind a service fingerprint.

    Exposed rather than summarised so a reader can judge the conclusion instead
    of trusting it. "We saw an SSH banner" and "the port number was 22" are very
    different qualities of evidence, and only the caller knows which is enough.
    """

    method: str | None = None
    detail: str | None = None


class ServiceOut(APIModel):
    id: str
    port: int
    protocol: str
    state: str
    service_name: str | None = Field(
        default=None,
        description="Fingerprint name. 'unknown' is a real answer; it is never guessed.",
    )
    product: str | None
    version: str | None
    banner: str | None
    fingerprint_confidence: Confidence
    fingerprint_evidence: list[ServiceFingerprintEvidence] = Field(default_factory=list)
    is_encrypted: bool
    is_administrative: bool
    is_database: bool
    first_seen: datetime
    last_seen: datetime


class CertificateOut(APIModel):
    id: str
    subject: str | None
    issuer: str | None
    serial_number: str | None
    not_before: datetime | None
    not_after: datetime | None
    days_until_expiry: int | None
    is_expired: bool
    is_self_signed: bool
    signature_algorithm: str | None
    key_size: int | None
    hostnames: list[str] = Field(default_factory=list)


class AssetContextOut(APIModel):
    business_criticality: BusinessCriticality
    data_classification: DataClassification
    business_function: BusinessFunction
    owner: AssetOwner
    owner_name: str | None
    business_description: str | None
    context_source: Provenance = Field(
        description="OBSERVED, INFERRED, or USER_PROVIDED. Never conflated."
    )
    context_confidence: Confidence
    updated_at: datetime


class AssetSummary(APIModel):
    id: str
    asset_key: str
    hostname: str | None
    ip_address: str | None
    domain: str | None
    asset_type: AssetType
    environment: Environment
    status: AssetStatus
    reachable: bool = Field(
        description="A port answered from the position Veyl scanned from. An observed fact."
    )
    internet_exposed: bool = Field(
        description=(
            "Registered by the organization as internet-facing. Veyl never infers this "
            "from reachability."
        )
    )
    authorization_status: AuthorizationStatus
    business_criticality: BusinessCriticality
    data_classification: DataClassification
    business_function: BusinessFunction
    owner: AssetOwner
    first_seen: datetime
    last_seen: datetime | None
    open_finding_count: int = 0
    highest_severity: Severity | None = None


class AssetDetail(AssetSummary):
    discovery_source: str
    source_provenance: Provenance
    scope_entry_id: str | None
    context_source: Provenance
    services: list[ServiceOut] = Field(default_factory=list)
    certificates: list[CertificateOut] = Field(default_factory=list)


class AssetContextUpdate(APIModel):
    """Business context supplied by a human.

    Every field is optional so a caller can correct one attribute without
    restating the rest. Fields that are omitted are left untouched, not reset.
    """

    business_criticality: BusinessCriticality | None = None
    data_classification: DataClassification | None = None
    business_function: BusinessFunction | None = None
    owner: AssetOwner | None = None
    owner_name: str | None = Field(default=None, max_length=200)
    business_description: str | None = Field(default=None, max_length=4000)
    internet_exposed: bool | None = Field(
        default=None,
        description="Set this to declare whether the asset faces the public internet.",
    )
    context_confidence: Confidence | None = None


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class EvidenceOut(APIModel):
    id: str
    kind: str
    summary: str
    detail: dict[str, Any]
    matcher: str
    provenance: Provenance
    confidence: Confidence
    observed_at: datetime
    checksum: str
    observation_id: str | None
    scan_id: str | None


class RemediationOut(APIModel):
    id: str
    owner: AssetOwner
    assignee_user_id: str | None
    priority: str
    due_date: datetime | None
    notes: str | None
    verified_at: datetime | None
    verified_by_scan_id: str | None
    verification_evidence: dict[str, Any] | None
    updated_at: datetime


class FindingEventOut(APIModel):
    id: str
    event_type: str
    from_value: str | None
    to_value: str | None
    detail: str | None
    actor_label: str
    created_at: datetime


class FindingSummary(APIModel):
    id: str
    dedup_key: str
    rule_id: str
    rule_category: str
    title: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    risk_score: float
    criticality_boost: float
    asset_id: str
    asset_key: str | None = None
    asset_hostname: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    reopen_count: int
    has_remediation: bool = False
    evidence_count: int = 0


class FindingDetail(FindingSummary):
    description: str
    detection_explanation: str = Field(
        description="How the rule decided this. Always present — a finding without one is a bug."
    )
    impact: str
    remediation_summary: str
    references: list[dict[str, str]] = Field(default_factory=list)
    vulnerability_refs: list[dict[str, Any]] = Field(default_factory=list)
    risk_factors: dict[str, Any] = Field(default_factory=dict)
    risk_explanation: str
    evidence: list[EvidenceOut] = Field(default_factory=list)
    remediation: RemediationOut | None = None
    history: list[FindingEventOut] = Field(default_factory=list)


class FindingStatusUpdate(APIModel):
    status: FindingStatus
    note: str | None = Field(default=None, max_length=2000)


class RemediationUpdate(APIModel):
    owner: AssetOwner | None = None
    assignee_user_id: str | None = None
    priority: Literal["LOW", "MEDIUM", "HIGH", "URGENT"] | None = None
    due_date: datetime | None = None
    notes: str | None = Field(default=None, max_length=4000)


# ---------------------------------------------------------------------------
# Changes
# ---------------------------------------------------------------------------


class ExposureChangeOut(APIModel):
    id: str
    scan_id: str
    previous_scan_id: str | None
    asset_id: str | None
    change_type: ChangeType
    significance: ChangeSignificance
    subject: str
    previous_state: str | None
    current_state: str | None
    evidence: dict[str, Any] = Field(default_factory=dict)
    security_significance: str = Field(
        description="Plain-language explanation of why this change matters, or why it may not."
    )
    is_risk_increasing: bool
    risk_score: float
    asset_criticality: BusinessCriticality | None
    asset_environment: Environment | None
    business_function: BusinessFunction | None
    acknowledged: bool
    detected_at: datetime


class ChangeAcknowledge(APIModel):
    acknowledged: bool = True


# ---------------------------------------------------------------------------
# Attack-surface graph
# ---------------------------------------------------------------------------


class GraphNodeOut(APIModel):
    id: str
    node_key: str
    node_type: str
    label: str
    ref_id: str | None
    properties: dict[str, Any] = Field(default_factory=dict)
    risk_score: float


class GraphEdgeOut(APIModel):
    id: str
    source_key: str
    target_key: str
    edge_type: str
    properties: dict[str, Any] = Field(default_factory=dict)
    weight: float = 1.0


class GraphOut(APIModel):
    nodes: list[GraphNodeOut] = Field(default_factory=list)
    edges: list[GraphEdgeOut] = Field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0


class AttackPathStep(APIModel):
    order: int | None = None
    description: str | None = None
    evidence: str | None = None
    node_key: str | None = None
    model_config = ConfigDict(from_attributes=True, extra="allow")


class AttackPathOut(APIModel):
    id: str
    name: str
    summary: str
    state: AttackPathState = Field(
        description="POTENTIAL unless an authorized check produced positive evidence."
    )
    confidence: Confidence
    risk_score: float
    node_keys: list[str] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    business_impact: str
    limitations: str = Field(
        description="What Veyl did not verify. Always populated; never claim more than was checked."
    )
    is_active: bool
    detected_at: datetime


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


class ReportRequest(APIModel):
    kind: ReportKind
    fmt: ReportFormat = ReportFormat.JSON
    scan_id: str | None = None
    title: str | None = Field(default=None, max_length=300)
    period_start: datetime | None = None
    period_end: datetime | None = None


class ReportOut(APIModel):
    id: str
    kind: ReportKind
    fmt: ReportFormat
    status: ReportStatus
    title: str
    scan_id: str | None
    checksum: str | None
    error_message: str | None
    period_start: datetime | None
    period_end: datetime | None
    created_at: datetime
    download_url: str | None = Field(
        default=None,
        description="Present only for a completed report. Relative to the API prefix.",
    )


# ---------------------------------------------------------------------------
# Rules, audit, health
# ---------------------------------------------------------------------------


class RuleOut(APIModel):
    rule_id: str
    title: str
    category: str
    severity: Severity
    description: str
    requires_observations: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[dict[str, str]] = Field(default_factory=list)


class AuditEntryOut(APIModel):
    id: str
    action: str
    actor_email: str | None
    actor_user_id: str | None
    actor_role: str | None
    resource_type: str | None
    resource_id: str | None
    result: str
    detail: str | None
    metadata: dict[str, Any] = Field(default_factory=dict)
    ip_address: str | None
    created_at: datetime
    prev_hash: str
    entry_hash: str


class AuditVerificationOut(APIModel):
    organization_id: str
    entries_checked: int
    is_valid: bool
    first_bad_entry_id: str | None = None
    reason: str | None = None
    checked_at: datetime


class FindingTrendPoint(APIModel):
    scan_id: str
    label: str | None
    finished_at: datetime | None
    open_total: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    new_findings: int
    resolved_findings: int


class DashboardSummary(APIModel):
    asset_count: int
    reachable_asset_count: int
    internet_exposed_asset_count: int
    scope_entry_count: int
    authorized_scope_entry_count: int
    open_finding_count: int
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    risk_increasing_changes_30d: int
    active_attack_path_count: int
    last_scan: ScanOut | None = None
    top_findings: list[FindingSummary] = Field(default_factory=list)


class HealthOut(APIModel):
    status: Literal["ok", "degraded"]
    version: str
    env: str
    database: str
    checks: dict[str, bool] = Field(default_factory=dict)
