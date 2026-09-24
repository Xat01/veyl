"""SQLAlchemy engine and session management.

The engine is created lazily and cached on the module, keyed by the database URL
it was built for. This matters more than it looks: ``veyl_api.config`` builds
its settings singleton at import time, so a module-level engine bound to
``settings.database_url`` would freeze the first URL the process ever saw. Any
later change to that URL — a test pointing at a scratch database, a CLI flag, a
worker reconfigured before startup — would be silently ignored, and every
component would keep talking to the original database. Resolving at call time
removes that whole class of bug, and it is what lets the test suite give each
test its own file.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from veyl_api.config import get_settings

_engine: Engine | None = None
_engine_url: str | None = None
_session_factory: sessionmaker[Session] | None = None


def _connect_args(url: str) -> dict:
    if url.startswith("sqlite"):
        # Needed because the worker runs scans in threads.
        return {"check_same_thread": False}
    return {}


def _build_engine(url: str) -> Engine:
    built = create_engine(
        url,
        echo=False,
        future=True,
        pool_pre_ping=True,
        connect_args=_connect_args(url),
    )

    if url.startswith("sqlite"):

        @event.listens_for(built, "connect")
        def _sqlite_pragmas(dbapi_connection, connection_record):  # noqa: ANN001, ARG001
            """Enable foreign keys and WAL on SQLite.

            Foreign-key enforcement is off by default in SQLite; Veyl relies on
            FK integrity for tenant scoping, so we turn it on explicitly.
            """
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return built


def get_engine() -> Engine:
    """Return the engine for the currently configured database URL.

    A single engine is reused while the URL is unchanged. If the URL changes,
    the previous engine is disposed and a new one is built, so no caller can be
    left holding a pool connected to the wrong database.
    """
    global _engine, _engine_url, _session_factory

    url = get_settings().database_url
    if _engine is None or _engine_url != url:
        if _engine is not None:
            _engine.dispose()
        _engine = _build_engine(url)
        _engine_url = url
        _session_factory = sessionmaker(
            bind=_engine, autoflush=False, autocommit=False, future=True
        )
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    """Return the session factory bound to the current engine."""
    get_engine()
    assert _session_factory is not None  # set by get_engine()
    return _session_factory


def dispose_engine() -> None:
    """Dispose the cached engine. Used by tests and by graceful shutdown."""
    global _engine, _engine_url, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _engine_url = None
    _session_factory = None


def __getattr__(name: str):
    """Keep ``engine`` and ``SessionLocal`` working as module attributes.

    Existing callers (scripts, the API lifespan, tests) refer to
    ``session.engine`` and ``session.SessionLocal``. Resolving them through
    ``__getattr__`` means they always reflect the current engine rather than a
    possibly-stale import-time binding.
    """
    if name == "engine":
        return get_engine()
    if name == "SessionLocal":
        return get_sessionmaker()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for scripts and workers."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
