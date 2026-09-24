"""Shared pytest fixtures for the Veyl test suite.

The suite is deliberately split by what it can prove:

* ``tests/unit`` — pure functions with no database and no network.
* ``tests/integration`` — real SQLite, real collector code, real rule evaluation.
* ``tests/security`` — the properties that must never regress: SSRF refusal,
  tenant isolation, evidence integrity, RBAC.

Every test that touches a database gets a fresh file per test, so one test can
never observe another test's rows.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for relative in (
    "apps/api",
    "packages/rules",
    "services/scanner",
    "services/analyzer",
    "services/correlation",
    "demo/targets",
):
    candidate = str(ROOT / relative)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

# Settings are read at import time, so the test environment must be established
# before any veyl module is imported. pytest imports conftest before test
# modules, which is why this lives here and not in a fixture.
os.environ.setdefault("VEYL_ENV", "test")
os.environ.setdefault("VEYL_SECRET_KEY", "test-secret-key-not-for-production-use")
os.environ.setdefault("VEYL_ALLOW_PRIVATE_TARGETS", "true")


@pytest.fixture()
def session(tmp_path, monkeypatch):
    """A fresh SQLite file per test, so no test can observe another's rows.

    Settings are memoised and the engine is cached against the URL it was built
    for, so both have to be reset here rather than imported once at module
    scope. ``dispose_engine`` actually closes the pooled connections; without
    it the next test's engine change would leave the previous file handle open
    and the drop_all below would fail on Windows.
    """
    db_path = tmp_path / f"veyl-test-{uuid.uuid4().hex}.db"
    monkeypatch.setenv("VEYL_DATABASE_URL", f"sqlite:///{db_path.as_posix()}")

    from veyl_api.config import reset_settings_cache
    from veyl_api.db import session as session_module
    from veyl_api.db.base import create_all, drop_all

    reset_settings_cache()
    session_module.dispose_engine()

    engine = session_module.get_engine()
    create_all(engine)
    db = session_module.get_sessionmaker()()
    try:
        yield db
    finally:
        db.close()
        drop_all(engine)
        session_module.dispose_engine()
        reset_settings_cache()


@pytest.fixture()
def organization(session):
    """A minimal tenant for tests that do not care about its details."""
    from veyl_api.models import Organization

    org = Organization(
        name="Test Org",
        slug=f"test-{uuid.uuid4().hex[:8]}",
        primary_domain="test.example",
    )
    session.add(org)
    session.commit()
    return org


@pytest.fixture()
def other_organization(session):
    """A second tenant, used to prove isolation between them."""
    from veyl_api.models import Organization

    org = Organization(
        name="Other Org",
        slug=f"other-{uuid.uuid4().hex[:8]}",
        primary_domain="other.example",
    )
    session.add(org)
    session.commit()
    return org


@pytest.fixture(scope="session")
def demo_server():
    """The bundled AcmePay demo service, started once for the whole session.

    Used by integration tests that need a real HTTP target. It is a real server
    on a real port; nothing about these tests is simulated.
    """
    import socket
    import threading

    from acmepay_service import build_server

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])

    httpd = build_server(port, "day7", verbose=False)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
