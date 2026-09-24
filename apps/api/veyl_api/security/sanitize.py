"""Input sanitisation and output encoding helpers.

Scan results are hostile input. These helpers are the boundary where that data
is neutralised before it reaches SQL, the filesystem, a shell, or a template.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

#: Characters that must never appear in a value destined for a filesystem path.
_UNSAFE_PATH_CHARS = re.compile(r'[\x00-\x1f<>:"/\\|?*]')

#: A conservative filename slug.
_SAFE_FILENAME_RE = re.compile(r"[^a-z0-9._-]+")

_MAX_STRING_LENGTH = 100_000
_MAX_JSON_DEPTH = 16


def sanitize_filename(name: str, *, fallback: str = "artifact", max_length: int = 120) -> str:
    """Reduce arbitrary text to a safe, predictable filename component.

    Prevents path traversal, NUL injection, Windows reserved names, and
    trailing-dot/space issues that some filesystems normalise silently.
    """
    value = unicodedata.normalize("NFKC", str(name)).strip()
    value = _UNSAFE_PATH_CHARS.sub("_", value)
    value = value.replace("..", "_")
    value = _SAFE_FILENAME_RE.sub("-", value.lower())
    value = value.strip(".-_")

    if len(value) > max_length:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        value = f"{value[: max_length - 9]}-{digest}"

    if not value:
        return fallback

    # Windows reserved device names.
    stem = value.split(".", 1)[0].upper()
    if stem in {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        value = f"_{value}"

    return value


def deep_sanitize_json(value: Any, *, depth: int = 0) -> Any:
    """Recursively neutralise a JSON-like structure from an untrusted source.

    * Truncates oversized strings.
    * Drops keys containing NUL or control characters.
    * Caps nesting depth to prevent stack exhaustion from pathological input.
    * Coerces non-JSON-native types to strings rather than dropping them.
    """
    if depth > _MAX_JSON_DEPTH:
        return "<truncated: nesting too deep>"

    if value is None or isinstance(value, bool | int | float):
        return value

    if isinstance(value, str):
        cleaned = "".join(
            ch for ch in value if ch == "\n" or ch == "\t" or ord(ch) >= 32
        )
        if len(cleaned) > _MAX_STRING_LENGTH:
            cleaned = cleaned[:_MAX_STRING_LENGTH] + "...<truncated>"
        return cleaned

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")[:1000]

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if any(ord(ch) < 32 for ch in key_text) or len(key_text) > 256:
                continue
            out[key_text] = deep_sanitize_json(item, depth=depth + 1)
        return out

    if isinstance(value, list | tuple | set):
        items = list(value)
        # Bound list length so a malicious response cannot blow up storage.
        return [deep_sanitize_json(i, depth=depth + 1) for i in items[:5000]]

    return str(value)[:1000]


def canonical_json(value: Any) -> str:
    """Deterministic JSON rendering, used for hashing and checksums."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def checksum(value: Any) -> str:
    """sha256 over the canonical JSON form of a value."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def truncate(text: str | None, limit: int = 500, suffix: str = "...") -> str:
    """Clamp a string for display and storage, never raising on None."""
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(suffix))] + suffix


def strip_control_characters(text: str) -> str:
    """Remove C0/C1 control characters except newline and tab."""
    return "".join(ch for ch in text if ch in "\n\t" or ord(ch) >= 32)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact values that are likely to carry credentials.

    Applied before HTTP response headers are persisted as evidence, so a
    leaked ``Set-Cookie`` or ``Authorization`` value never lands in the
    database or in a shared report.
    """
    sensitive = {
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "www-authenticate",
    }
    out: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in sensitive:
            out[key] = "<redacted by Veyl>"
        elif lower == "location":
            out[key] = _redact_url_credentials(value)
        else:
            out[key] = truncate(strip_control_characters(str(value)), 800)
    return out


def _redact_url_credentials(url: str) -> str:
    """Strip userinfo from a URL so credentials in a Location header are not stored."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return truncate(url, 800)
    if parsed.username or parsed.password:
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        parsed = parsed._replace(netloc=netloc)
    return truncate(parsed.geturl(), 800)


def is_safe_relative_path(path: str) -> bool:
    """True when ``path`` is a relative path with no traversal components."""
    if not path or path.startswith(("/", "\\")):
        return False
    if ":" in path.split("/")[0]:  # Windows drive letter
        return False
    normalized = path.replace("\\", "/")
    return ".." not in normalized.split("/")


def safe_join(base: str | Path, *parts: str) -> Path:
    """Join path components, refusing anything that escapes ``base``.

    Returns a ``Path`` rather than a string because every caller immediately
    treats the result as one (``.parent``, ``.is_file()``, ``.read_text()``), and
    a bare ``str`` fails on those in ways that only show up at runtime.

    Uses the standard library's ``os.path.commonpath`` check rather than string
    prefix matching, which is defeated by symlinks and case differences.
    """
    import os

    base_text = os.fspath(base)
    for part in parts:
        if not is_safe_relative_path(part):
            raise ValueError(f"refusing unsafe path component: {part!r}")
    target = os.path.normpath(os.path.join(base_text, *parts))
    base_norm = os.path.normpath(base_text)
    if os.path.commonpath([os.path.abspath(target), os.path.abspath(base_norm)]) != os.path.abspath(
        base_norm
    ):
        raise ValueError(f"path escapes base directory: {target!r}")
    return Path(target)
