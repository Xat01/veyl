"""Health and readiness endpoints.

Health is deliberately split from readiness. ``/health`` answers "is this
process alive" and is cheap enough for a liveness probe to call every few
seconds. ``/health/ready`` answers "can this instance actually serve traffic"
by checking the database, and is what a load balancer should gate on.
"""

from __future__ import annotations

from fastapi import APIRouter

from veyl_api.api.schemas import HealthOut
from veyl_api.config import settings

router = APIRouter()


@router.get("/health", response_model=HealthOut, summary="Liveness probe")
def health() -> HealthOut:
    """Report that the process is running. Does not touch the database."""
    return HealthOut(
        status="ok",
        version=_version(),
        env=settings.env,
        database=settings.database_url.split("://", 1)[0],
        checks={"process": True},
    )


@router.get("/healthz", response_model=HealthOut, include_in_schema=False)
def healthz() -> HealthOut:
    """Alias for ``/health`` for convention-driven probes."""
    return health()


@router.get("/health/ready", response_model=HealthOut, summary="Readiness probe")
def readiness() -> HealthOut:
    """Report whether this instance can serve requests, including its database."""
    from veyl_api.api.main import _database_reachable

    db_ok = _database_reachable()
    return HealthOut(
        status="ok" if db_ok else "degraded",
        version=_version(),
        env=settings.env,
        database=settings.database_url.split("://", 1)[0],
        checks={"process": True, "database": db_ok},
    )


def _version() -> str:
    from veyl_api.api.main import API_VERSION

    return API_VERSION
