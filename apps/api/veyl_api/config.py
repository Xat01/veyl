"""Application configuration.

Every knob that changes safety behaviour lives here and is documented in
``.env.example``. Configuration is validated at import time so a misconfigured
deployment fails fast rather than silently scanning something it should not.
"""

from __future__ import annotations

import ipaddress
import re
from contextlib import contextmanager
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PORT_RANGE_RE = re.compile(r"^\s*(\d{1,5})\s*(?:-\s*(\d{1,5})\s*)?$")


def parse_port_spec(spec: str) -> list[int]:
    """Expand a port specification such as ``"1-1024,8443"`` into a sorted list.

    Raises:
        ValueError: if any token is not a valid 1-65535 port or range.
    """
    ports: set[int] = set()
    for token in spec.split(","):
        if not token.strip():
            continue
        match = _PORT_RANGE_RE.match(token)
        if not match:
            raise ValueError(f"invalid port specification token: {token!r}")
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else start
        if start > end:
            raise ValueError(f"inverted port range: {token!r}")
        for port in range(start, end + 1):
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of range in {token!r}")
            ports.add(port)
    if not ports:
        raise ValueError("port specification resolved to an empty set")
    return sorted(ports)


class Settings(BaseSettings):
    """Runtime configuration for the Veyl API and worker."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_prefix="VEYL_",
        extra="ignore",
        case_sensitive=False,
    )

    # -- Core ---------------------------------------------------------------
    env: Literal["development", "test", "staging", "production"] = "development"
    app_name: str = "Veyl"
    api_prefix: str = "/api"

    secret_key: str = Field(
        default="dev-insecure-secret-key-do-not-use-in-production",
        description="HMAC key for JWTs and the audit-log hash chain.",
    )
    access_token_ttl_minutes: int = 60
    refresh_token_ttl_days: int = 7

    # -- Database -----------------------------------------------------------
    database_url: str = "sqlite:///./veyl.db"

    # -- Safety floor -------------------------------------------------------
    allow_private_targets: bool = False
    always_block_metadata: bool = True
    allowed_scan_ports: str = "1-1024,3306,3389,5432,6379,8000-8100,8443,9000,9200,27017"
    scan_timeout_seconds: float = 5.0
    scan_max_concurrency: int = 64
    scan_max_ports_per_run: int = 4096
    scan_user_agent: str = "Veyl-Exposure-Intelligence/0.1 (+authorized-assessment-only)"

    # -- Nmap (optional) ----------------------------------------------------
    nmap_enabled: bool = False
    nmap_binary: str = "nmap"

    # -- Threat intel -------------------------------------------------------
    cve_provider: Literal["local", "osv", "none"] = "local"
    osv_api_url: str = "https://api.osv.dev"

    # -- AI assistance ------------------------------------------------------
    ai_enabled: bool = False
    ai_base_url: str | None = None
    ai_api_key: str | None = None
    ai_model: str | None = None

    # -- Rate limiting ------------------------------------------------------
    rate_limit_per_minute: int = 120

    trust_proxy_headers: bool = Field(
        default=False,
        description=(
            "Honor X-Forwarded-For for the client address recorded in the audit log. "
            "Enable only when a trusted reverse proxy sets the header; otherwise a "
            "caller can write an arbitrary address into the audit trail."
        ),
    )

    # -- Artifacts ----------------------------------------------------------
    artifact_dir: str = Field(
        default="./artifacts",
        description="Directory for generated report files. Paths are always resolved under it.",
    )

    # -- CORS ---------------------------------------------------------------
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @field_validator("secret_key")
    @classmethod
    def _reject_weak_key_in_production(cls, value: str, info) -> str:
        # `info.data` may not yet contain `env`; validate in the model validator.
        return value

    @model_validator(mode="after")
    def _enforce_production_hygiene(self) -> Settings:
        if self.env == "production":
            weak = (
                "dev-insecure-secret-key-do-not-use-in-production",
                "change-me-generate-with-openssl-rand-hex-32",
                "",
            )
            if self.secret_key in weak or len(self.secret_key) < 32:
                raise ValueError(
                    "VEYL_SECRET_KEY must be set to a strong value (>=32 chars) in production"
                )
            if self.allow_private_targets:
                raise ValueError(
                    "VEYL_ALLOW_PRIVATE_TARGETS must be false in production; internal "
                    "scanning belongs to a separate trusted deployment."
                )
        return self

    # -- Derived helpers ----------------------------------------------------
    @property
    def allowed_ports(self) -> list[int]:
        return parse_port_spec(self.allowed_scan_ports)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


def _build_metadata_addresses() -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Cloud metadata endpoints that must never be reachable from a scanner."""
    return (
        ipaddress.ip_address("169.254.169.254"),  # AWS / Azure / GCP / Oracle IMDS
        ipaddress.ip_address("169.254.170.2"),  # AWS ECS task metadata
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
        ipaddress.ip_address("192.0.0.192"),  # Oracle Cloud
        ipaddress.ip_address("fd00:ec2::254"),  # AWS IMDS over IPv6
    )


METADATA_ADDRESSES = _build_metadata_addresses()


#: Stack of active :func:`overridden_settings` replacements. The innermost one
#: wins, so nested overrides compose the way a reader would expect.
_settings_overrides: list[Settings] = []


@lru_cache(maxsize=1)
def _build_settings() -> Settings:
    """Construct settings from the environment. Memoised by ``get_settings``."""
    return Settings()


def get_settings() -> Settings:
    """Return the settings in force right now.

    Resolves through the override stack first, then falls back to the
    environment-derived singleton. This is the only supported way to read
    configuration, which is what keeps ``reset_settings_cache`` and
    ``overridden_settings`` effective for every caller.
    """
    if _settings_overrides:
        return _settings_overrides[-1]
    return _build_settings()


def reset_settings_cache() -> None:
    """Drop the cached settings so the next call re-reads the environment.

    Needed by tests, which point the process at a scratch database per test,
    and by any tooling that reconfigures the process after import.
    """
    _build_settings.cache_clear()


class _SettingsProxy:
    """A stand-in for the settings singleton that always resolves the current one.

    ``veyl_api.config.settings`` is imported by name in a dozen modules. Binding
    the real object there would freeze the configuration at import time: any
    later change to the environment would be visible to ``get_settings()`` but
    invisible to every module that had already imported the old object, which is
    a genuinely confusing failure ("the engine points at one database and the
    scanner uses another"). This proxy keeps every existing import working while
    always deferring to the live settings.

    Assignment is refused on purpose. A module that could write to ``settings``
    could silently change the safety posture of the whole process at any moment,
    which is exactly the kind of invisible state change this codebase avoids.
    Use :func:`overridden_settings` when a temporary change is genuinely needed.
    """

    __slots__ = ()

    def __getattr__(self, name: str):
        return getattr(get_settings(), name)

    def __setattr__(self, name: str, value) -> None:
        raise AttributeError(
            "settings is read-only; use veyl_api.config.overridden_settings(...) "
            "for a temporary change, or set the corresponding VEYL_* environment "
            "variable before the process starts"
        )

    def __repr__(self) -> str:
        return f"<settings proxy -> {get_settings()!r}>"


@contextmanager
def overridden_settings(**overrides: object):
    """Temporarily replace settings values for the duration of the block.

    Exists so tests (and tooling that must simulate a different deployment) can
    exercise a posture such as ``env="production"`` without leaking the change
    past the block or mutating a process-wide object in place.

    The previous settings object is restored on exit, including when the block
    raises, so an exception cannot leave the process configured for a different
    environment than it started in.

    Yields:
        The overridden settings instance.

    Raises:
        ValueError: if an override names a field that does not exist, so a typo
            fails loudly instead of being silently ignored.

    Example::

        with overridden_settings(env="production", allow_private_targets=False):
            ...
    """
    unknown = sorted(set(overrides) - set(Settings.model_fields))
    if unknown:
        raise ValueError(f"unknown settings field(s): {', '.join(unknown)}")

    replacement = get_settings().model_copy(update=overrides)
    _settings_overrides.append(replacement)
    try:
        yield replacement
    finally:
        _settings_overrides.pop()


settings: Settings = _SettingsProxy()  # type: ignore[assignment]
