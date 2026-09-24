"""Persistence-layer tests.

The first test in this file is the one that matters most. Declaring an enum
column as ``String`` makes SQLAlchemy return a plain ``str`` on load, so every
``is``/``is not`` comparison against the enum silently evaluates to False even
though the stored value is correct. That defect is invisible to a test that only
constructs objects in memory, and it produced a real bug in this codebase: the
scope guard raised ``AttributeError`` on ``entry.authorization_status.value``
and the failure surfaced only as "nothing was scanned".

Every enum-backed column is therefore round-tripped through a real database
here, so a regression of that class cannot ship.
"""

from __future__ import annotations

from veyl_api.db.base import Base, EnumType, utcnow
from veyl_api.enums import (
    AssetOwner,
    AuthorizationStatus,
    Environment,
    ScanStatus,
)
from veyl_api.models import Asset, Scan, ScopeEntry


def test_enum_columns_round_trip_as_enum_members(session, organization):
    """A persisted enum must come back as the enum, not as a plain string."""
    session.add(
        ScopeEntry(
            organization_id=organization.id,
            domain="roundtrip.example",
            environment=Environment.STAGING,
            asset_owner=AssetOwner.SECURITY_TEAM,
            authorization_status=AuthorizationStatus.AUTHORIZED,
            authorized_by="test",
            authorized_at=utcnow(),
        )
    )
    session.commit()
    session.expunge_all()

    loaded = session.query(ScopeEntry).filter_by(domain="roundtrip.example").one()

    assert loaded.environment is Environment.STAGING
    assert loaded.asset_owner is AssetOwner.SECURITY_TEAM
    assert loaded.authorization_status is AuthorizationStatus.AUTHORIZED
    # The identity check is the whole point. These enums are StrEnum subclasses,
    # so `!= "AUTHORIZED"` would be False even for the bug — value equality is
    # satisfied by a plain str. Only the *type* distinguishes the fixed version.
    assert isinstance(loaded.authorization_status, AuthorizationStatus)


def test_is_authorized_now_works_after_db_load(session, organization):
    """The property that gates scanning must behave on a loaded row."""
    session.add(
        ScopeEntry(
            organization_id=organization.id,
            domain="auth.example",
            authorization_status=AuthorizationStatus.AUTHORIZED,
            authorized_at=utcnow(),
        )
    )
    session.add(
        ScopeEntry(
            organization_id=organization.id,
            domain="pending.example",
            authorization_status=AuthorizationStatus.PENDING,
        )
    )
    session.commit()
    session.expunge_all()

    authorized = session.query(ScopeEntry).filter_by(domain="auth.example").one()
    pending = session.query(ScopeEntry).filter_by(domain="pending.example").one()

    assert authorized.is_authorized_now is True
    assert pending.is_authorized_now is False


def test_every_enum_column_uses_enum_type(session):
    """No enum-annotated column may be left as a bare String.

    This walks the Python annotations on the mapped classes and checks the
    corresponding column's type. It is a structural test: it fails the moment
    somebody adds ``Mapped[Severity] = mapped_column(String(32))``, which is the
    mistake that produced the original bug.
    """
    from enum import Enum

    offenders: list[str] = []
    for mapper in Base.registry.mappers:
        cls = mapper.class_
        annotations = _collect_annotations(cls)
        for key, annotation in annotations.items():
            if key not in mapper.columns:
                continue
            # Unwrap Optional[...] / X | None into the inner types.
            inner = _unwrap_optional(annotation)
            enum_members = [
                t for t in inner if isinstance(t, type) and issubclass(t, Enum)
            ]
            if not enum_members:
                continue
            column_type = mapper.columns[key].type
            if not isinstance(column_type, EnumType):
                offenders.append(
                    f"{cls.__name__}.{key} is {type(column_type).__name__}, "
                    f"expected EnumType"
                )

    assert offenders == [], (
        "enum columns stored as plain String break identity comparisons after a "
        "database round trip:\n  " + "\n  ".join(offenders)
    )


def _collect_annotations(cls) -> dict[str, object]:
    """All annotations on a class and its bases, in resolution order."""
    import typing

    collected: dict[str, object] = {}
    for base in reversed(cls.__mro__):
        collected.update(getattr(base, "__annotations__", {}) or {})
    # SQLAlchemy stores the resolved annotation too; prefer it when present.
    try:
        collected.update(typing.get_type_hints(cls, include_extras=False))
    except Exception:  # pragma: no cover - defensive; hints may be unresolvable
        pass
    return collected


def _unwrap_optional(annotation) -> list:
    """Flatten ``Optional[X]`` / ``X | None`` / ``Mapped[X]`` into a list of types."""
    import typing

    origin = typing.get_origin(annotation)
    if origin is typing.Union or str(origin).endswith("UnionType"):
        out: list = []
        for arg in typing.get_args(annotation):
            if arg is type(None):
                continue
            out.extend(_unwrap_optional(arg))
        return out
    if origin is not None:
        args = typing.get_args(annotation)
        if args:
            out = []
            for arg in args:
                out.extend(_unwrap_optional(arg))
            return out
    return [annotation]


def test_asset_reachable_and_internet_exposed_are_separate_facts(session, organization):
    """Reachability is observed; internet exposure is asserted. They must differ."""
    from veyl_api.enums import AssetType

    asset = Asset(
        organization_id=organization.id,
        asset_key="internal.example",
        hostname="internal.example",
        asset_type=AssetType.DOMAIN,
        environment=Environment.PRODUCTION,
        status="ACTIVE",
        first_seen=utcnow(),
        last_seen=utcnow(),
    )
    session.add(asset)
    session.commit()
    session.expunge_all()

    loaded = session.query(Asset).filter_by(asset_key="internal.example").one()
    assert loaded.reachable is False
    assert loaded.internet_exposed is False


def test_timestamps_are_timezone_aware_after_load(session, organization):
    """UTC timestamps must not lose their tzinfo across the SQLite boundary."""
    scope = ScopeEntry(
        organization_id=organization.id,
        domain="tz.example",
        authorized_at=utcnow(),
    )
    session.add(scope)
    session.commit()
    session.expunge_all()

    loaded = session.query(ScopeEntry).filter_by(domain="tz.example").one()
    assert loaded.authorized_at.tzinfo is not None
    assert loaded.created_at.tzinfo is not None


def test_enum_round_trips_through_scan_row(session, organization):
    """A Scan's status enum must survive a load, not just an insert."""
    from veyl_api.enums import ScanTrigger

    scan = Scan(
        organization_id=organization.id,
        status=ScanStatus.QUEUED,
        trigger=ScanTrigger.MANUAL,
        scanner_backend="tcp_connect",
        started_at=utcnow(),
        scope_entry_ids=[],
    )
    session.add(scan)
    session.commit()
    session.expunge_all()

    loaded = session.query(Scan).one()
    assert loaded.status is ScanStatus.QUEUED
    assert loaded.trigger is ScanTrigger.MANUAL
