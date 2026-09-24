"""SQLAlchemy declarative base and shared column helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """Timezone-aware UTC now, used for every timestamp Veyl writes."""
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Stores naive-UTC in the database, returns timezone-aware UTC in Python.

    SQLite has no native timezone support, and ``DateTime(timezone=True)`` on
    SQLite silently drops the offset. Normalising here keeps comparisons correct
    regardless of backend.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        if value.tzinfo is None:
            return value
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for all Veyl tables."""


class UUIDPrimaryKey:
    """Mixin adding a string UUID primary key.

    UUIDs are stored as 36-char strings so the same schema works on SQLite and
    PostgreSQL without dialect-specific UUID types.
    """

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )


class Timestamped:
    """Mixin adding creation and modification timestamps."""

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class OrgScoped:
    """Mixin marking a table as belonging to a single tenant.

    Every query against a table carrying this mixin MUST be filtered by
    ``organization_id``. The API layer enforces this centrally; see
    ``veyl_api.deps``.
    """

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
