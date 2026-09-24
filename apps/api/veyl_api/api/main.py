"""FastAPI application factory.

Middleware order matters and is deliberately explicit:

1. ``RequestIdMiddleware`` — assigns a correlation id first, so every log line
   and error response can be traced back to one request.
2. ``SecurityHeadersMiddleware`` — applies defensive headers to every response,
   including error responses generated further up the stack.
3. ``RateLimitMiddleware`` — bounds how fast a caller can consume the API.
4. ``CORSMiddleware`` — outermost, so a preflight is answered before any of the
   above do work.

The OpenAPI docs are disabled outside development. A security tool's API schema
describes exactly what an attacker would want to enumerate, and shipping it in
production is a choice that should be made on purpose, not by default.
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware

from veyl_api.api.routes import (
    assets,
    attack_paths,
    audit,
    auth,
    changes,
    findings,
    graph,
    health,
    members,
    reports,
    rules,
)
from veyl_api.config import settings
from veyl_api.db.base import Base

logger = logging.getLogger("veyl.api")

API_VERSION = "0.1.0"

#: Headers applied to every response. These are defensive defaults for an API
#: that returns security data; they cost nothing and prevent an entire class of
#: browser-side issues.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
}


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request id, and echo it back so a client can cite it in a report."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply defensive response headers, including on error responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        # HSTS only makes sense over TLS; setting it on a plain-HTTP dev server
        # would make the browser refuse to talk to localhost again.
        if settings.env == "production":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """A simple fixed-window limiter keyed by client address.

    This is intentionally modest: it exists to stop a single caller from
    hammering the API, not to be a distributed quota system. A real deployment
    puts a rate limiter at the edge. The limit is applied after authentication is
    possible but before routing, so unauthenticated floods are also bounded.
    """

    def __init__(self, app, *, limit_per_minute: int) -> None:
        super().__init__(app)
        self.limit = limit_per_minute
        self._window_start = time.monotonic()
        self._counts: dict[str, int] = {}

    async def dispatch(self, request: Request, call_next):
        # Health checks must never be rate limited away; a monitor hitting a
        # 429 would report the service as down.
        if request.url.path.endswith("/health") or request.url.path.endswith("/healthz"):
            return await call_next(request)

        now = time.monotonic()
        if now - self._window_start >= 60:
            self._window_start = now
            self._counts.clear()

        client = request.client.host if request.client else "unknown"
        self._counts[client] = self._counts.get(client, 0) + 1
        if self._counts[client] > self.limit:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": (
                        f"rate limit exceeded: at most {self.limit} requests per minute "
                        "per client address"
                    )
                },
                headers={"Retry-After": "60"},
            )
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Prepare the database on startup.

    ``create_all`` is used for SQLite development only. Managed deployments use
    migrations, and running ``create_all`` against Postgres would silently skip
    changes to existing tables, which is exactly the class of drift a migration
    system exists to prevent.
    """
    from veyl_api.db.session import engine

    if settings.is_sqlite:
        Base.metadata.create_all(engine)
        logger.info("sqlite schema ensured at %s", settings.database_url)
    yield


def create_app() -> FastAPI:
    """Build the Veyl API application."""
    docs_enabled = settings.env in ("development", "test")

    app = FastAPI(
        title=f"{settings.app_name} API",
        version=API_VERSION,
        description=(
            "Continuous exposure intelligence: asset discovery, exposure monitoring, "
            "evidence-backed findings, attack-surface correlation, business context, "
            "and remediation tracking. Scanning operates only against explicitly "
            "authorized scope."
        ),
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Organization", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(RateLimitMiddleware, limit_per_minute=settings.rate_limit_per_minute)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)

    # A validation error must never echo the submitted value back: the value may
    # be a password, and FastAPI's default error body includes the input.
    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        safe_errors = []
        for error in exc.errors():
            safe_errors.append(
                {
                    "loc": list(error.get("loc", [])),
                    "msg": error.get("msg", "invalid value"),
                    "type": error.get("type", "value_error"),
                }
            )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "request validation failed", "errors": safe_errors},
        )

    @app.exception_handler(Exception)
    async def _unhandled_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", "unknown")
        # Log the detail server-side; return a reference, not a stack trace.
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "internal server error",
                "request_id": request_id,
            },
        )

    prefix = settings.api_prefix
    app.include_router(health.router, prefix=prefix, tags=["health"])
    app.include_router(auth.router, prefix=f"{prefix}/auth", tags=["auth"])
    app.include_router(members.router, prefix=f"{prefix}/members", tags=["members"])
    app.include_router(assets.scope_router, prefix=f"{prefix}/scope", tags=["scope"])
    app.include_router(assets.router, prefix=f"{prefix}/assets", tags=["assets"])
    app.include_router(assets.scans_router, prefix=f"{prefix}/scans", tags=["scans"])
    app.include_router(findings.router, prefix=f"{prefix}/findings", tags=["findings"])
    app.include_router(changes.router, prefix=f"{prefix}/changes", tags=["changes"])
    app.include_router(graph.router, prefix=f"{prefix}/graph", tags=["graph"])
    app.include_router(attack_paths.router, prefix=f"{prefix}/attack-paths", tags=["attack-paths"])
    app.include_router(reports.router, prefix=f"{prefix}/reports", tags=["reports"])
    app.include_router(rules.router, prefix=f"{prefix}/rules", tags=["rules"])
    app.include_router(audit.router, prefix=f"{prefix}/audit", tags=["audit"])
    app.include_router(assets.dashboard_router, prefix=f"{prefix}/dashboard", tags=["dashboard"])

    return app


app = create_app()


def _database_reachable() -> bool:
    """Probe the database for the health endpoint."""
    from veyl_api.db.session import engine

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 - health must never raise
        return False


__all__ = ["app", "create_app", "_database_reachable", "API_VERSION"]
