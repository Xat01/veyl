"""The bundled web console.

These tests cover the parts of the console that can be checked without a
browser: that it is actually served, that the browser gets a policy strict
enough to matter, and that serving a directory of files did not open a path
traversal. The behaviour inside the page is exercised separately by
``scripts/console_e2e.mjs``, which drives a real browser.

The distinction is deliberate. A test that asserts a button exists proves the
markup was written; only a browser proves the button does something.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from veyl_api.api.main import create_app


@pytest.fixture()
def client(session):
    from veyl_api.api import deps

    app = create_app()

    def _override_session():
        yield session

    app.dependency_overrides[deps.get_session] = _override_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_console_is_served_at_its_own_path(client):
    response = client.get("/console/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert "VEYL" in body
    # The page must reference its assets relatively so it works under the mount.
    assert 'src="app.js"' in body
    assert 'href="styles.css"' in body


def test_console_assets_are_served(client):
    for asset in ("app.js", "styles.css"):
        response = client.get(f"/console/{asset}")
        assert response.status_code == 200, asset
        assert len(response.content) > 1000, asset


def test_console_gets_a_strict_content_security_policy(client):
    response = client.get("/console/")
    policy = response.headers.get("content-security-policy", "")
    assert "default-src 'self'" in policy
    assert "script-src 'self'" in policy
    # An unsafe-inline exception would defeat the purpose of shipping a policy.
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy


def test_the_api_does_not_get_the_console_policy(client):
    """The console policy must not be applied to /docs, which needs inline JS."""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers


def test_bare_host_redirects_to_the_console(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (307, 308)
    assert response.headers["location"].endswith("/console/")


def test_path_traversal_out_of_the_console_directory_is_refused(client):
    """Serving a directory must not serve the directory's parents.

    Both encodings are tried: some stacks decode ``%2e%2e`` before routing and
    some after, and the guard has to hold either way.
    """
    for path in ("/console/../SECURITY.md", "/console/%2e%2e/SECURITY.md",
                 "/console/..%2fSECURITY.md"):
        response = client.get(path)
        assert response.status_code in (400, 404), path
        assert "disclosure" not in response.text.lower(), path


def test_console_does_not_leak_the_database_file(client):
    """A convenient static mount must not turn into a file server for the repo."""
    for path in ("/console/veyl.db", "/console/../veyl.db", "/console/%2e%2e/veyl.db"):
        response = client.get(path)
        assert response.status_code in (400, 404), path
