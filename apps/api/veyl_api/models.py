"""Core domain models.

Design notes
------------
* Multi-tenancy is enforced by ``organization_id`` on every tenant table
  (``OrgScoped``). There is no cross-tenant table without an explicit owner.
* Nothing about a scan result is trusted. Observations are stored verbatim in
  ``Observation`` rows and only turned into ``Finding`` rows by deterministic
  rules that must cite observations as evidence.
* Business context (``AssetContext``) is stored separately from observed asset
  facts so that Veyl can always answer "did we measure this, infer it, or were
  we told it?"
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from veyl_api.db.base import (
    Base,
    EnumType,
    OrgScoped,
    Timestamped,
    UTCDateTime,
    UUIDPrimaryKey,
)
from veyl_api.enums import (
    AssetOwner,
    AssetStatus,
    AssetType,
    AttackPathState,
    AuditAction,
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
    RuleCategory,
    ScanStatus,
    ScanTrigger,
    Severity,
)

# =============================================================================
# Tenancy and identity
# =============================================================================


class Organization(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    primary_domain: Mapped[str | None] = mapped_column(String(255))
    industry: Mapped[str | None] = mapped_column(String(120))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    members: Mapped[list[OrganizationMember]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class User(UUIDPrimaryKey, Timestamped, Base):
    """A human account. Identity is global; authorization is per-organization."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    memberships: Mapped[list[OrganizationMember]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class OrganizationMember(UUIDPrimaryKey, Timestamped, Base):
    """Binds a user to an organization with exactly one role."""

    __tablename__ = "organization_members"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_member_org_user"),
        Index("ix_member_org_role", "organization_id", "role"),
    )

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[OrganizationRole] = mapped_column(
        EnumType("veyl_api.enums:OrganizationRole",
        length=32), nullable=False,
    )
    title: Mapped[str | None] = mapped_column(String(120))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="members")
    user: Mapped[User] = relationship(back_populates="memberships")


# =============================================================================
# Scope registry — the authorization boundary
# =============================================================================


class ScopeEntry(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """An explicitly authorized target.

    Veyl refuses to scan any host that does not resolve to at least one active,
    non-expired ``AUTHORIZED`` scope entry. This table *is* the authorization
    boundary; see ``veyl_api.safety.scope.ScopeGuard``.
    """

    __tablename__ = "scope_entries"
    __table_args__ = (
        Index("ix_scope_org_domain", "organization_id", "domain"),
        Index("ix_scope_org_auth", "organization_id", "authorization_status"),
    )

    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    cidr: Mapped[str | None] = mapped_column(String(64))
    environment: Mapped[Environment] = mapped_column(
        EnumType("veyl_api.enums:Environment", length=32), default=Environment.UNKNOWN, nullable=False
    )
    asset_owner: Mapped[AssetOwner] = mapped_column(
        EnumType("veyl_api.enums:AssetOwner", length=32), default=AssetOwner.UNASSIGNED, nullable=False
    )
    authorization_status: Mapped[AuthorizationStatus] = mapped_column(
        EnumType("veyl_api.enums:AuthorizationStatus", length=32),
        default=AuthorizationStatus.PENDING,
        nullable=False,
    )
    authorized_by: Mapped[str | None] = mapped_column(String(200))
    authorized_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    notes: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Explicit opt-in to scan beyond the default safe port set for this target.
    allow_port_override: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    assets: Mapped[list[Asset]] = relationship(back_populates="scope_entry")

    @property
    def is_authorized_now(self) -> bool:
        """True when the entry is active, authorized, and not expired."""
        from veyl_api.db.base import utcnow

        if not self.is_active or self.authorization_status is not AuthorizationStatus.AUTHORIZED:
            return False
        return self.expires_at is None or self.expires_at > utcnow()


# =============================================================================
# Assets and observations
# =============================================================================


class Asset(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """A thing that belongs to the organization and can be assessed."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "asset_key", name="uq_asset_org_key"),
        Index("ix_asset_org_type", "organization_id", "asset_type"),
        Index("ix_asset_org_status", "organization_id", "status"),
        Index("ix_asset_org_exposed", "organization_id", "internet_exposed"),
        Index("ix_asset_org_reachable", "organization_id", "reachable"),
    )

    #: Stable natural key within the tenant, e.g. "api.acmepay.example" or "203.0.113.10".
    asset_key: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    domain: Mapped[str | None] = mapped_column(String(255))
    asset_type: Mapped[AssetType] = mapped_column(
        EnumType("veyl_api.enums:AssetType",
        length=32), nullable=False,
    )
    environment: Mapped[Environment] = mapped_column(
        EnumType("veyl_api.enums:Environment", length=32), default=Environment.UNKNOWN, nullable=False
    )
    status: Mapped[AssetStatus] = mapped_column(
        EnumType("veyl_api.enums:AssetStatus", length=32), default=AssetStatus.ACTIVE, nullable=False
    )

    #: Whether the asset is reachable *from the position Veyl scanned from*.
    #: This is an observed fact: the port sweep either connected or it did not.
    reachable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    #: Whether the asset faces the public internet. This is a claim about the
    #: asset's network position that a scanner cannot establish by connecting to
    #: it, so it is never set from scan results. It is only set from the
    #: organization's own asset context or scope metadata, and it defaults to
    #: False (unknown/not established) rather than being inferred from
    #: reachability. Conflating the two would let Veyl describe an internal host
    #: as "internet-exposed" purely because a scan reached it.
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    authorization_status: Mapped[AuthorizationStatus] = mapped_column(
        EnumType("veyl_api.enums:AuthorizationStatus", length=32),
        default=AuthorizationStatus.PENDING,
        nullable=False,
    )

    # Provenance of the *existence* of this asset.
    discovery_source: Mapped[str] = mapped_column(String(64), default="scope_scan", nullable=False)
    source_provenance: Mapped[Provenance] = mapped_column(
        EnumType("veyl_api.enums:Provenance", length=32), default=Provenance.OBSERVED, nullable=False
    )

    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    scope_entry_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scope_entries.id", ondelete="SET NULL")
    )

    # Denormalised business context for fast list rendering. The authoritative
    # record is AssetContext, which carries per-field provenance.
    business_criticality: Mapped[BusinessCriticality] = mapped_column(
        EnumType("veyl_api.enums:BusinessCriticality", length=32), default=BusinessCriticality.LOW, nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        EnumType("veyl_api.enums:DataClassification", length=32), default=DataClassification.PUBLIC, nullable=False
    )
    business_function: Mapped[BusinessFunction] = mapped_column(
        EnumType("veyl_api.enums:BusinessFunction", length=32), default=BusinessFunction.OTHER, nullable=False
    )
    owner: Mapped[AssetOwner] = mapped_column(
        EnumType("veyl_api.enums:AssetOwner", length=32), default=AssetOwner.UNASSIGNED, nullable=False
    )
    context_source: Mapped[Provenance] = mapped_column(
        EnumType("veyl_api.enums:Provenance", length=32), default=Provenance.INFERRED, nullable=False
    )

    scope_entry: Mapped[ScopeEntry | None] = relationship(back_populates="assets")
    services: Mapped[list[Service]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(back_populates="asset")
    context: Mapped[AssetContext | None] = relationship(
        back_populates="asset", uselist=False, cascade="all, delete-orphan"
    )
    certificates: Mapped[list[Certificate]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    observations: Mapped[list[Observation]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class AssetContext(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """Authoritative business context with per-field provenance.

    ``Asset`` carries denormalised copies for fast queries; this table records
    where each value came from and who set it.
    """

    __tablename__ = "asset_contexts"

    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    business_criticality: Mapped[BusinessCriticality] = mapped_column(
        EnumType("veyl_api.enums:BusinessCriticality", length=32), default=BusinessCriticality.LOW, nullable=False
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        EnumType("veyl_api.enums:DataClassification", length=32), default=DataClassification.PUBLIC, nullable=False
    )
    business_function: Mapped[BusinessFunction] = mapped_column(
        EnumType("veyl_api.enums:BusinessFunction", length=32), default=BusinessFunction.OTHER, nullable=False
    )
    owner: Mapped[AssetOwner] = mapped_column(
        EnumType("veyl_api.enums:AssetOwner", length=32), default=AssetOwner.UNASSIGNED, nullable=False
    )
    owner_name: Mapped[str | None] = mapped_column(String(200))
    business_description: Mapped[str | None] = mapped_column(Text)
    context_source: Mapped[Provenance] = mapped_column(
        EnumType("veyl_api.enums:Provenance", length=32), default=Provenance.USER_PROVIDED, nullable=False
    )
    context_confidence: Mapped[Confidence] = mapped_column(
        EnumType("veyl_api.enums:Confidence", length=32), default=Confidence.HIGH, nullable=False
    )
    updated_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    asset: Mapped[Asset] = relationship(back_populates="context")


class Service(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """A listening service discovered on an asset during a scan."""

    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_service_asset_port_proto"),
        Index("ix_service_org_port", "organization_id", "port"),
    )

    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp", nullable=False)
    state: Mapped[str] = mapped_column(String(16), default="open", nullable=False)

    #: Fingerprint name, e.g. "ssh", "https", "mysql". "unknown" is a valid and
    #: preferred answer over a wrong guess.
    service_name: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    product: Mapped[str | None] = mapped_column(String(120))
    version: Mapped[str | None] = mapped_column(String(120))
    banner: Mapped[str | None] = mapped_column(Text)
    fingerprint_confidence: Mapped[Confidence] = mapped_column(
        EnumType("veyl_api.enums:Confidence", length=32), default=Confidence.LOW, nullable=False
    )
    #: JSON list of {"method": ..., "detail": ...} describing how we concluded this.
    fingerprint_evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_administrative: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_database: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    internet_reachable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="services")


class Certificate(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """A TLS certificate observed on an asset's endpoint."""

    __tablename__ = "certificates"
    __table_args__ = (
        Index("ix_cert_org_expiry", "organization_id", "not_after"),
        Index("ix_cert_fingerprint", "organization_id", "fingerprint_sha256"),
    )

    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    serial_number: Mapped[str | None] = mapped_column(String(128))
    san: Mapped[list[str]] = mapped_column(JSON, default=list)
    not_before: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    not_after: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    chain_valid: Mapped[bool | None] = mapped_column(Boolean)
    hostname_valid: Mapped[bool | None] = mapped_column(Boolean)
    tls_version: Mapped[str | None] = mapped_column(String(32))
    cipher_suite: Mapped[str | None] = mapped_column(String(120))
    signature_algorithm: Mapped[str | None] = mapped_column(String(120))
    key_size: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="certificates")

    @property
    def days_remaining(self) -> int | None:
        from veyl_api.db.base import utcnow

        if self.not_after is None:
            return None
        return (self.not_after - utcnow()).days


# =============================================================================
# Scans and raw observations
# =============================================================================


class Scan(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """One authorized assessment run against a set of scope entries."""

    __tablename__ = "scans"
    __table_args__ = (Index("ix_scan_org_started", "organization_id", "started_at"),)

    status: Mapped[ScanStatus] = mapped_column(
        EnumType("veyl_api.enums:ScanStatus", length=32), default=ScanStatus.QUEUED, nullable=False, index=True
    )
    trigger: Mapped[ScanTrigger] = mapped_column(
        EnumType("veyl_api.enums:ScanTrigger", length=32), default=ScanTrigger.MANUAL, nullable=False
    )
    label: Mapped[str | None] = mapped_column(String(200))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    scope_entry_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    ports_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scanner_backend: Mapped[str] = mapped_column(String(32), default="tcp_connect", nullable=False)

    targets_requested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    targets_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    targets_blocked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    assets_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    services_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    changes_detected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    error_message: Mapped[str | None] = mapped_column(Text)
    #: Targets refused by the safety floor, with the reason. Surfaced in the UI.
    blocked_targets: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    observations: Mapped[list[Observation]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    # `exposure_changes` has two FK paths to `scans` (scan_id, previous_scan_id),
    # so the join must name the owning column explicitly.
    changes: Mapped[list[ExposureChange]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        foreign_keys="ExposureChange.scan_id",
    )


class Observation(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """A verbatim fact recorded during a scan.

    Observations are the only place scan output is stored as produced. Rules
    never re-run network calls; they read observations. This makes every finding
    reproducible and auditable, and it means a malicious or malformed scanner
    response can never become a finding without passing a rule.
    """

    __tablename__ = "observations"
    __table_args__ = (
        Index("ix_obs_scan_kind", "scan_id", "kind"),
        Index("ix_obs_org_kind", "organization_id", "kind"),
    )

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    #: Collector that produced this, e.g. "dns", "tcp_scan", "tls", "http".
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Specific check within the collector, e.g. "http_headers", "cert_chain".
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    provenance: Mapped[Provenance] = mapped_column(
        EnumType("veyl_api.enums:Provenance", length=32), default=Provenance.OBSERVED, nullable=False
    )
    confidence: Mapped[Confidence] = mapped_column(
        EnumType("veyl_api.enums:Confidence", length=32), default=Confidence.HIGH, nullable=False
    )
    #: Structured payload. Treated as hostile input everywhere downstream.
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="observations")
    asset: Mapped[Asset | None] = relationship(back_populates="observations")


class AssetSnapshot(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """Immutable per-asset state captured at the end of a scan.

    Change detection compares consecutive snapshots. Storing a normalised
    fingerprint of the whole asset state means detection is a pure function of
    two rows, which is why it is testable without any network access.
    """

    __tablename__ = "asset_snapshots"
    __table_args__ = (Index("ix_snapshot_scan_asset", "scan_id", "asset_id"),)

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    captured_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    #: {"ports": {...}, "services": {...}, "certificate": {...}, "http": {...}, "dns": {...}}
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: sha256 over a canonicalised ``state``; equality means "nothing changed".
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    port_states: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    service_signatures: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)


# =============================================================================
# Findings, evidence, remediation
# =============================================================================


class RuleDefinitionRecord(UUIDPrimaryKey, Timestamped, Base):
    """Persisted catalogue of rule metadata.

    The executable logic lives in ``packages/rules``; this table only mirrors
    metadata so the UI can render the catalogue and so findings remain
    interpretable even if a rule is later retired.
    """

    __tablename__ = "rule_definitions"

    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[RuleCategory] = mapped_column(
        EnumType("veyl_api.enums:RuleCategory",
        length=32), nullable=False,
    )
    severity: Mapped[Severity] = mapped_column(EnumType("veyl_api.enums:Severity", length=32), nullable=False)
    default_confidence: Mapped[Confidence] = mapped_column(
        EnumType("veyl_api.enums:Confidence",
        length=32), nullable=False,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    detection: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_requirements: Mapped[list[str]] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    references: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    runtime_ms_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    times_evaluated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    times_triggered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class Finding(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """A rule violation, bound to exactly one asset and backed by evidence."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "dedup_key", name="uq_finding_org_dedup"),
        Index("ix_finding_org_status_sev", "organization_id", "status", "severity"),
        Index("ix_finding_org_asset", "organization_id", "asset_id"),
        Index("ix_finding_org_last_seen", "organization_id", "last_seen_at"),
    )

    #: Stable identity across scans, e.g. "VEYL-WEB-001:assetid:443".
    #: A finding that reappears after being resolved is reopened, not duplicated.
    dedup_key: Mapped[str] = mapped_column(String(255), nullable=False)

    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_category: Mapped[RuleCategory] = mapped_column(
        EnumType("veyl_api.enums:RuleCategory",
        length=32), nullable=False,
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[Severity] = mapped_column(EnumType("veyl_api.enums:Severity", length=32), nullable=False)
    confidence: Mapped[Confidence] = mapped_column(
        EnumType("veyl_api.enums:Confidence",
        length=32), nullable=False,
    )

    status: Mapped[FindingStatus] = mapped_column(
        EnumType("veyl_api.enums:FindingStatus", length=32), default=FindingStatus.OPEN, nullable=False
    )

    description: Mapped[str] = mapped_column(Text, nullable=False)
    detection_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_summary: Mapped[str] = mapped_column(Text, nullable=False)
    references: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)

    #: Optional CVEs, each with an explicit affected/not-affected state.
    #: A CVE is only attached when product *and* version evidence exists.
    vulnerability_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    # -- Risk model: transparent, inspectable factors ----------------------
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_factors: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    risk_explanation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    #: Set when business context materially raised priority, so the UI can say why.
    criticality_boost: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    first_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL")
    )
    last_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL")
    )
    #: Number of times the finding has gone RESOLVED -> OPEN.
    reopen_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="findings")
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    remediation: Mapped[Remediation | None] = relationship(
        back_populates="finding", uselist=False, cascade="all, delete-orphan"
    )
    history: Mapped[list[FindingEvent]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """Proof attached to a finding.

    Evidence is always a verbatim excerpt of an ``Observation``. It is never
    generated, summarised, or paraphrased — especially not by an LLM.
    """

    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_finding", "finding_id", "created_at"),)

    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    observation_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("observations.id", ondelete="SET NULL")
    )
    scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Human-readable one-liner, e.g. "HTTP response headers from https://host:443/".
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    #: Verbatim machine-readable excerpt copied out of the observation.
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    matcher: Mapped[str] = mapped_column(String(200), nullable=False)
    provenance: Mapped[Provenance] = mapped_column(
        EnumType("veyl_api.enums:Provenance", length=32), default=Provenance.OBSERVED, nullable=False
    )
    confidence: Mapped[Confidence] = mapped_column(
        EnumType("veyl_api.enums:Confidence", length=32), default=Confidence.HIGH, nullable=False
    )
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    #: sha256 of the canonical ``detail`` payload, for tamper detection in reports.
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class Remediation(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """Remediation workflow state for one finding."""

    __tablename__ = "remediations"

    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    owner: Mapped[AssetOwner] = mapped_column(
        EnumType("veyl_api.enums:AssetOwner", length=32), default=AssetOwner.UNASSIGNED, nullable=False
    )
    assignee_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    priority: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    due_date: Mapped[datetime | None] = mapped_column(UTCDateTime)
    notes: Mapped[str | None] = mapped_column(Text)

    #: Populated by the scan that no longer reproduced the finding.
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    verified_by_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL")
    )
    #: Evidence captured at verification time proving the condition is gone.
    verification_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    finding: Mapped[Finding] = relationship(back_populates="remediation")


class FindingEvent(UUIDPrimaryKey, OrgScoped, Base):
    """Append-only audit trail of everything that happened to a finding."""

    __tablename__ = "finding_events"
    __table_args__ = (Index("ix_finding_event_finding", "finding_id", "created_at"),)

    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    from_value: Mapped[str | None] = mapped_column(String(255))
    to_value: Mapped[str | None] = mapped_column(String(255))
    detail: Mapped[str | None] = mapped_column(Text)
    actor_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_label: Mapped[str] = mapped_column(String(200), default="system", nullable=False)
    scan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scans.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)

    finding: Mapped[Finding] = relationship(back_populates="history")


class VulnerabilityRecord(UUIDPrimaryKey, Timestamped, Base):
    """Cached vulnerability-intelligence record.

    Global (not tenant-scoped) because it is public reference data. Veyl only
    ever populates this from a configured provider, never from inference.
    """

    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(120))
    severity: Mapped[Severity | None] = mapped_column(
        EnumType("veyl_api.enums:Severity", length=32)
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    affected_product: Mapped[str] = mapped_column(String(200), nullable=False)
    affected_version_ranges: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    modified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


# =============================================================================
# Exposure change detection
# =============================================================================


class ExposureChange(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """A single difference between two consecutive scans."""

    __tablename__ = "exposure_changes"
    __table_args__ = (
        Index("ix_change_org_detected", "organization_id", "detected_at"),
        Index("ix_change_org_type", "organization_id", "change_type"),
        Index("ix_change_org_significance", "organization_id", "significance"),
    )

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    previous_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL")
    )
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    change_type: Mapped[ChangeType] = mapped_column(
        EnumType("veyl_api.enums:ChangeType",
        length=48), nullable=False,
    )
    significance: Mapped[ChangeSignificance] = mapped_column(
        EnumType("veyl_api.enums:ChangeSignificance",
        length=32), nullable=False,
    )
    subject: Mapped[str] = mapped_column(String(255), nullable=False)

    previous_state: Mapped[str | None] = mapped_column(Text)
    current_state: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    security_significance: Mapped[str] = mapped_column(Text, default="", nullable=False)

    #: Business context snapshot at detection time, denormalised so the change
    #: remains interpretable even if the asset is later reclassified.
    asset_criticality: Mapped[BusinessCriticality | None] = mapped_column(
        EnumType("veyl_api.enums:BusinessCriticality", length=32)
    )
    asset_environment: Mapped[Environment | None] = mapped_column(
        EnumType("veyl_api.enums:Environment", length=32)
    )
    business_function: Mapped[BusinessFunction | None] = mapped_column(
        EnumType("veyl_api.enums:BusinessFunction", length=48)
    )
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_risk_increasing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    scan: Mapped[Scan] = relationship(
        back_populates="changes", foreign_keys=[scan_id]
    )


# =============================================================================
# Attack-surface graph
# =============================================================================


class GraphNode(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """A node in the attack-surface graph.

    Materialised rather than computed on read so the graph is queryable and so
    historical graphs remain reconstructable.
    """

    __tablename__ = "graph_nodes"
    __table_args__ = (
        UniqueConstraint("organization_id", "node_key", name="uq_graph_node_org_key"),
        Index("ix_graph_node_org_type", "organization_id", "node_type"),
    )

    node_key: Mapped[str] = mapped_column(String(300), nullable=False)
    node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(300), nullable=False)
    #: Reference to the underlying entity (asset id, finding id, ...).
    ref_id: Mapped[str | None] = mapped_column(String(36), index=True)
    properties: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class GraphEdge(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    __tablename__ = "graph_edges"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "source_key", "target_key", "edge_type", name="uq_graph_edge"
        ),
        Index("ix_graph_edge_org_source", "organization_id", "source_key"),
        Index("ix_graph_edge_org_target", "organization_id", "target_key"),
    )

    source_key: Mapped[str] = mapped_column(String(300), nullable=False)
    target_key: Mapped[str] = mapped_column(String(300), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(32), nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)


class AttackPath(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    """A correlated chain of exposures that *could* compound.

    Veyl is careful with language here. Unless an authorized non-destructive
    check produced positive evidence, ``state`` stays ``POTENTIAL`` and every
    rendered string says "potential attack path".
    """

    __tablename__ = "attack_paths"
    __table_args__ = (Index("ix_path_org_score", "organization_id", "risk_score"),)

    name: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[AttackPathState] = mapped_column(
        EnumType("veyl_api.enums:AttackPathState", length=32), default=AttackPathState.POTENTIAL, nullable=False
    )
    confidence: Mapped[Confidence] = mapped_column(
        EnumType("veyl_api.enums:Confidence", length=32), default=Confidence.MEDIUM, nullable=False
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    #: Ordered list of graph node keys forming the chain.
    node_keys: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: Ordered human-readable steps, each with the evidence backing it.
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    finding_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    asset_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    business_impact: Mapped[str] = mapped_column(Text, default="", nullable=False)
    #: Why Veyl is *not* claiming exploitation.
    limitations: Mapped[str] = mapped_column(Text, default="", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_evaluated_scan_id: Mapped[str | None] = mapped_column(String(36))
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


# =============================================================================
# Reporting and audit
# =============================================================================


class Report(UUIDPrimaryKey, Timestamped, OrgScoped, Base):
    __tablename__ = "reports"
    __table_args__ = (Index("ix_report_org_created", "organization_id", "created_at"),)

    kind: Mapped[ReportKind] = mapped_column(EnumType("veyl_api.enums:ReportKind", length=32), nullable=False)
    fmt: Mapped[ReportFormat] = mapped_column(
        EnumType("veyl_api.enums:ReportFormat",
        length=16), nullable=False,
    )
    status: Mapped[ReportStatus] = mapped_column(
        EnumType("veyl_api.enums:ReportStatus", length=32), default=ReportStatus.PENDING, nullable=False
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scans.id", ondelete="SET NULL"))
    generated_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    #: Relative path under the artifacts directory. Never an absolute path from user input.
    artifact_path: Mapped[str | None] = mapped_column(String(500))
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error_message: Mapped[str | None] = mapped_column(Text)
    #: sha256 of the rendered artifact so a download can be verified.
    checksum: Mapped[str | None] = mapped_column(String(64))
    period_start: Mapped[datetime | None] = mapped_column(UTCDateTime)
    period_end: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AuditLog(UUIDPrimaryKey, OrgScoped, Base):
    """Tamper-evident audit trail.

    Each row stores the hash of the previous row for the same organization plus
    its own content hash. Deleting or editing a row breaks the chain, and
    ``AuditLog.verify_chain`` detects it.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_org_created", "organization_id", "created_at"),
        Index("ix_audit_org_action", "organization_id", "action"),
    )

    action: Mapped[AuditAction] = mapped_column(
        EnumType("veyl_api.enums:AuditAction",
        length=48), nullable=False,
    )
    actor_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_email: Mapped[str | None] = mapped_column(String(320))
    actor_role: Mapped[str | None] = mapped_column(String(32))
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    result: Mapped[str] = mapped_column(String(16), default="SUCCESS", nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
