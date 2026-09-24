"""SQLAlchemy declarative base and shared column helpers."""

from __future__ import annotations

import importlib
import uuid
from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import DateTime, String, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """Timezone-aware UTC now, used for every timestamp Veyl writes."""
    return datetime.now(UTC)


class EnumType(TypeDecorator):
    """Persists a ``StrEnum`` member as its value and restores the member on load.

    Declaring an enum column as ``String`` looks harmless and is not: SQLAlchemy
    hands back a plain ``str``, so every ``is``/``is not`` comparison in the
    codebase silently evaluates to ``False`` even when the stored value is
    correct. That failure mode is invisible in a unit test that constructs
    objects in memory and only appears once data round-trips through the
    database — precisely the situation this decorator removes.

    The enum class is resolved from its import path lazily so that
    ``veyl_api.db.base`` does not have to import ``veyl_api.enums`` at module
    import time.
    """

    impl = String
    cache_ok = True

    def __init__(self, enum_path: str, length: int = 48) -> None:
        super().__init__(length=length)
        if ":" not in enum_path:
            raise ValueError(
                f"EnumType expects 'module:Class', received {enum_path!r}"
            )
        module_name, _, class_name = enum_path.partition(":")
        self.enum_path = enum_path
        self._module_name = module_name
        self._class_name = class_name
        self._enum_class: type[Enum] | None = None

    @property
    def enum_class(self) -> type[Enum]:
        if self._enum_class is None:
            module = importlib.import_module(self._module_name)
            resolved = getattr(module, self._class_name)
            if not issubclass(resolved, Enum):
                raise TypeError(f"{self.enum_path} is not an Enum")
            self._enum_class = resolved
        return self._enum_class

    def process_bind_param(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        if isinstance(value, Enum):
            return value.value
        # Accept the raw string form as well, so constructing a model with a
        # literal like "OPEN" is coerced rather than stored inconsistently.
        return self.enum_class(value).value

    def process_result_value(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        if isinstance(value, Enum):
            return value
        try:
            return self.enum_class(value)
        except ValueError:
            # A value the current code no longer knows about. Surfacing the raw
            # string is more useful than raising during row materialisation, and
            # it keeps an older row readable after an enum is narrowed.
            return value


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
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


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
