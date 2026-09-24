"""HTTP/HTTPS collection: response metadata, security headers, technology hints.

Every request goes through
:func:`veyl_scanner.http.safe_get`, which pins the connection to an address that
has already passed the safety floor. Redirects are never followed blindly —
each hop is validated and re-checked, and the chain is capped.

Nothing in this module assigns severity. It records what the server did; rules
decide what that means.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from veyl_api.config import settings
from veyl_api.enums import Confidence, Provenance
from veyl_api.security.sanitize import redact_headers, truncate
from veyl_scanner.contracts import CollectResult, CollectorRegistration, ObservationPayload, ScanRequest

#: Security-relevant response headers we always record verbatim.
INTERESTING_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "via",
    "x-cache",
    "location",
    "set-cookie",
    "x-robots-tag",
    "content-type",
)

#: Paths probed only with a plain GET and no crawling. All are conventionally
#: public metadata documents; none are destructive.
DISCOVERY_PATHS: tuple[str, ...] = (
    "/",
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/.git/config",
    "/.env",
    "/server-status",
    "/.well-known/openid-configuration",
)

#: Response bodies are only kept for a bounded prefix; enough to fingerprint,
#: never enough to be a data-exfiltration vector.
_MAX_BODY_BYTES = 65536


@dataclass
class HttpHop:
    """One request/response exchange, recorded as observed."""

    url: str
    final_url: str
    status_code: int | None
    reason: str | None
    headers: dict[str, str]
    body_prefix: str
    body_length: int
    elapsed_ms: float | None
    tls: dict[str, Any] | None
    error: str | None = None
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)


def _build_ssl_context(*, verify: bool) -> ssl.SSLContext:
    """Build a TLS context.

    Verification is relaxed for certificate *collection* only. An expired or
    self-signed certificate is precisely the thing we need to observe and report,
    so refusing to connect would hide the finding. The relaxed context is used
    to read the peer certificate; it never protects a credentialed request and
    no data from the request is trusted.
    """
    if verify:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Keep a sane floor so we still exercise real TLS negotiation.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _peer_certificate_summary(sock: ssl.SSLSocket) -> dict[str, Any]:
    """Extract TLS session and certificate facts from an established socket."""
    summary: dict[str, Any] = {}
    try:
        summary["tls_version"] = sock.version()
        cipher = sock.cipher()
        if cipher:
            summary["cipher_suite"], summary["tls_version_protocol"], summary["cipher_bits"] = cipher
        cert = sock.getpeercert()
        if cert:
            summary["subject"] = {
                k: v for item in cert.get("subject", ()) for k, v in item
            }
            summary["issuer"] = {k: v for item in cert.get("issuer", ()) for k, v in item}
            summary["not_before"] = cert.get("notBefore")
            summary["not_after"] = cert.get("notAfter")
            summary["san"] = [v for k, v in cert.get("subjectAltName", ()) if k.lower() == "dns"]
            summary["serial_number"] = cert.get("serialNumber")
            summary["version"] = cert.get("version")
    except (ssl.SSLError, ValueError, KeyError) as exc:
        summary["error"] = f"certificate inspection failed: {exc}"

    # The DER form gives us a fingerprint and full extension detail without
    # trusting the parsed dict above.
    try:
        der = sock.getpeercert(binary_form=True)
        if der:
            import hashlib

            summary["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
            summary["der_length"] = len(der)
    except (ssl.SSLError, ValueError):
        pass
    return summary


def safe_get(
    url: str,
    *,
    timeout: float,
    user_agent: str,
    allow_redirects: bool = False,
    max_redirects: int = 5,
    validate_hook: Any = None,
) -> HttpHop:
    """Perform a single GET against ``url``, resolving through vetted addresses.

    ``validate_hook`` is called with each hop's hostname before connecting; the
    runner passes the scope guard's check so a redirect to an out-of-scope host
    is refused rather than followed.

    Raw ``http.client`` is used rather than a convenience HTTP library because we
    need explicit control over which IP is dialled and over the TLS context.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    hop = HttpHop(
        url=url,
        final_url=url,
        status_code=None,
        reason=None,
        headers={},
        body_prefix="",
        body_length=0,
        elapsed_ms=None,
        tls=None,
    )

    if validate_hook is not None:
        allowed = validate_hook(host)
        if not allowed:
            hop.error = "redirect target refused by scope guard"
            return hop

    # Resolve here so we dial a specific validated address.
    try:
        from veyl_api.safety.firewall import validate_target

        validated = validate_target(host, allow_dns=True)
    except Exception as exc:  # UnsafeTargetError and anything unexpected
        hop.error = f"target refused: {exc}"
        return hop

    address = validated.addresses[0]
    tls_info: dict[str, Any] | None = None

    import time

    started = time.perf_counter()
    raw_sock: socket.socket | None = None
    try:
        raw_sock = socket.create_connection((address, port), timeout=timeout)

        if scheme == "https":
            context = _build_ssl_context(verify=False)
            server_hostname = host if ipaddress.ip_address(address).is_global else None
            tls_sock = context.wrap_socket(raw_sock, server_hostname=server_hostname)
            raw_sock = tls_sock
            tls_info = _peer_certificate_summary(tls_sock)
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=context
            )
            conn.sock = tls_sock
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.sock = raw_sock

        conn.putrequest("GET", path, skip_host=False, skip_accept_encoding=False)
        conn.putheader("Host", host if port in (80, 443) else f"{host}:{port}")
        conn.putheader("User-Agent", user_agent)
        conn.putheader("Accept", "*/*")
        conn.putheader("Connection", "close")
        conn.endheaders()

        response = conn.getresponse()
        body = response.read(_MAX_BODY_BYTES)
        remaining = response.length
        hop.status_code = response.status
        hop.reason = response.reason
        hop.headers = redact_headers({k: v for k, v in response.getheaders()})
        hop.body_prefix = truncate(body.decode("utf-8", errors="replace"), 20000)
        hop.body_length = len(body) if remaining is None else max(len(body), -1)
        hop.tls = tls_info
        hop.elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
        conn.close()
    except (TimeoutError, socket.timeout):
        hop.error = "request timed out"
    except ssl.SSLError as exc:
        hop.error = f"TLS error: {exc}"
    except (http.client.HTTPException, OSError, ValueError) as exc:
        hop.error = f"request failed: {exc}"
    finally:
        if raw_sock is not None:
            try:
                raw_sock.close()
            except OSError:
                pass

    # Record the redirect chain explicitly so rules can reason about it.
    if (
        allow_redirects
        and hop.status_code in (301, 302, 303, 307, 308)
        and hop.headers.get("Location")
        and len(hop.redirect_chain) < max_redirects
    ):
        target = urljoin(url, hop.headers["Location"])
        hop.redirect_chain.append(
            {"from": url, "to": target, "status": hop.status_code}
        )
        nxt = safe_get(
            target,
            timeout=timeout,
            user_agent=user_agent,
            allow_redirects=allow_redirects,
            max_redirects=max_redirects - 1,
            validate_hook=validate_hook,
        )
        nxt.redirect_chain = hop.redirect_chain + nxt.redirect_chain
        return nxt

    return hop


def header_map(headers: dict[str, str]) -> dict[str, str]:
    """Lowercase-keyed view of a header dict, first value wins."""
    out: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower not in out:
            out[lower] = value
    return out


def parse_cookie_attributes(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Parse Set-Cookie flags without a cookies library.

    Records HttpOnly/Secure/SameSite/Path for each cookie. These attributes are
    exactly what VEYL-WEB cookie rules need, and recording them here means the
    rules only read observations.
    """
    cookies: list[dict[str, Any]] = []
    raw_values = [
        value for key, value in headers.items() if key.lower() == "set-cookie"
    ]
    for raw in raw_values:
        for chunk in raw.split(","):
            parts = [p.strip() for p in chunk.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name = parts[0].split("=", 1)[0].strip()
            flags = {p.split("=", 1)[0].lower().strip() for p in parts[1:]}
            cookies.append(
                {
                    "name": name,
                    "httponly": "httponly" in flags,
                    "secure": "secure" in flags,
                    "samesite": next(
                        (
                            p.split("=", 1)[1].strip()
                            for p in parts[1:]
                            if p.lower().startswith("samesite=")
                        ),
                        None,
                    ),
                }
            )
    return cookies


def detect_technologies(headers: dict[str, str], body: str) -> list[dict[str, str]]:
    """Infer technologies from headers and body markers.

    High-confidence entries come from headers the server volunteers. Body
    markers are recorded with lower confidence. ``product`` and ``version`` are
    only set when the evidence actually names them — a bare ``nginx`` header
    yields a product but no version, and we leave version as ``None`` rather
    than inventing one.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    body_lower = body.lower()
    found: list[dict[str, str]] = []

    server = lowered.get("server", "")
    if server:
        product, version = _split_server_banner(server)
        found.append(
            {
                "product": product,
                "version": version,
                "source": "Server header",
                "confidence": "HIGH",
                "evidence": truncate(server, 200),
            }
        )

    powered = lowered.get("x-powered-by", "")
    if powered:
        product, version = _split_server_banner(powered)
        found.append(
            {
                "product": product,
                "version": version,
                "source": "X-Powered-By header",
                "confidence": "HIGH",
                "evidence": truncate(powered, 200),
            }
        )

    generator = lowered.get("x-generator", "")
    if generator:
        product, version = _split_server_banner(generator)
        found.append(
            {
                "product": product,
                "version": version,
                "source": "X-Generator header",
                "confidence": "HIGH",
                "evidence": truncate(generator, 200),
            }
        )

    aspnet = lowered.get("x-aspnet-version")
    if aspnet:
        found.append(
            {
                "product": "ASP.NET",
                "version": aspnet.strip(),
                "source": "X-AspNet-Version header",
                "confidence": "HIGH",
                "evidence": truncate(aspnet, 200),
            }
        )

    for marker, product, source in (
        ("wp-content", "wordpress", "body marker wp-content"),
        ("<meta name=\"generator\" content=\"wordpress", "wordpress", "body meta generator"),
        ("drupal-settings-json", "drupal", "body marker drupal-settings-json"),
        ("__next_data__", "next.js", "body marker __NEXT_DATA__"),
        ("__remixcontext", "remix", "body marker __remixContext"),
        ("ng-version=", "angular", "body marker ng-version"),
    ):
        if marker in body_lower:
            found.append(
                {
                    "product": product,
                    "version": None,
                    "source": source,
                    "confidence": "MEDIUM",
                    "evidence": f"matched {source}",
                }
            )

    return found


def _split_server_banner(banner: str) -> tuple[str, str | None]:
    """Split "nginx/1.24.0 (Ubuntu)" into ("nginx", "1.24.0").

    Returns ``None`` for the version when nothing version-like is present, which
    is the common case for hardened servers and is the correct answer.
    """
    text = banner.strip()
    product = text
    version: str | None = None
    for token in text.replace("(", " ").replace(")", " ").split():
        if "/" in token:
            head, tail = token.split("/", 1)
            product = head
            candidate = tail.split()[0] if tail.split() else ""
            if any(ch.isdigit() for ch in candidate):
                version = candidate
            break
    else:
        # Server header with no version, e.g. "Apache" or "cloudflare".
        product = text.split()[0] if text.split() else text
    return product.strip() or "unknown", version


class HttpCollector:
    """Collects HTTP/HTTPS facts and probes public metadata paths."""

    name = "http"
    registration = CollectorRegistration(
        name="http",
        description=(
            "Records status, headers, cookies, technology hints, TLS session data and "
            "probes public metadata paths (OpenAPI, security.txt, robots.txt and similar)."
        ),
        produces=[
            "http_response",
            "http_security_headers",
            "http_cookies",
            "http_tech",
            "http_discovery_path",
            "http_tls",
        ],
        requires_ports=[80, 443, 8080, 8443, 8000, 8888],
    )

    def __init__(
        self,
        *,
        probe_paths: bool = True,
        discover_paths: bool = True,
        validate_hook: Any = None,
    ) -> None:
        self.probe_paths = probe_paths
        self.discover_paths = discover_paths
        self.validate_hook = validate_hook

    def collect(self, request: ScanRequest) -> CollectResult:
        result = CollectResult()
        https_ports = [p for p in request.ports if p in (443, 8443) or p > 1024]
        http_ports = [p for p in request.ports if p in (80, 8080)]

        if 443 in request.ports or 8443 in request.ports:
            self._probe_scheme(request, "https", result, prefer=[p for p in (443, 8443) if p in request.ports])
        if 80 in request.ports or 8080 in request.ports:
            self._probe_scheme(request, "http", result, prefer=[p for p in (80, 8080) if p in request.ports])

        # Any other open high port is worth a quick HTTP probe: this is how
        # Veyl finds the staging service a developer left running on 8081.
        extra = [p for p in request.ports if p not in {80, 443, 8080, 8443} and p > 1024]
        if extra:
            self._probe_scheme(request, "https", result, prefer=extra[:4])

        return result

    def _probe_scheme(
        self,
        request: ScanRequest,
        scheme: str,
        result: CollectResult,
        *,
        prefer: list[int],
    ) -> None:
        for port in prefer:
            host = request.hostname
            default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
            authority = host if default_port else f"{host}:{port}"
            base_url = f"{scheme}://{authority}"

            hop = safe_get(
                base_url + "/",
                timeout=request.timeout_seconds,
                user_agent=request.user_agent,
                allow_redirects=request.follow_redirects,
                validate_hook=self.validate_hook,
            )

            if hop.error and hop.status_code is None:
                # Not an HTTP service on this port. Record the negative result
                # rather than inventing a service.
                result.observations.append(
                    ObservationPayload(
                        kind="http_probe_failed",
                        subject=f"{host}:{port}",
                        asset_key=host,
                        data={
                            "hostname": host,
                            "port": port,
                            "scheme": scheme,
                            "error": hop.error,
                        },
                        confidence=Confidence.HIGH,
                        summary=f"No HTTP response on {scheme}://{authority} ({hop.error})",
                    )
                )
                continue

            headers = hop.headers
            header_lookup = header_map(headers)

            result.observations.append(
                ObservationPayload(
                    kind="http_response",
                    subject=f"{host}:{port}",
                    asset_key=host,
                    data={
                        "hostname": host,
                        "port": port,
                        "scheme": scheme,
                        "url": hop.url,
                        "final_url": hop.final_url,
                        "status_code": hop.status_code,
                        "reason": hop.reason,
                        "elapsed_ms": hop.elapsed_ms,
                        "redirect_chain": hop.redirect_chain,
                        "body_prefix": hop.body_prefix[:8192],
                        "is_admin_path": any(
                            marker in hop.final_url.lower()
                            for marker in ("/admin", "/manage", "/console", "/phpmyadmin")
                        ),
                    },
                    confidence=Confidence.HIGH,
                    summary=f"HTTP {hop.status_code} {hop.reason or ''} from {scheme}://{authority}/".strip(),
                )
            )

            security_headers = {
                name: header_lookup.get(name) for name in INTERESTING_HEADERS
            }
            result.observations.append(
                ObservationPayload(
                    kind="http_security_headers",
                    subject=f"{host}:{port}",
                    asset_key=host,
                    data={
                        "hostname": host,
                        "port": port,
                        "scheme": scheme,
                        "headers": security_headers,
                        "present": [k for k, v in security_headers.items() if v],
                        "absent": [k for k, v in security_headers.items() if not v],
                    },
                    confidence=Confidence.HIGH,
                    summary=(
                        f"Security headers on {scheme}://{authority}/: "
                        f"{len([v for v in security_headers.values() if v])} present, "
                        f"{len([v for v in security_headers.values() if not v])} absent"
                    ),
                )
            )

            cookies = parse_cookie_attributes(headers)
            if cookies:
                result.observations.append(
                    ObservationPayload(
                        kind="http_cookies",
                        subject=f"{host}:{port}",
                        asset_key=host,
                        data={"hostname": host, "port": port, "cookies": cookies},
                        confidence=Confidence.HIGH,
                        summary=f"{len(cookies)} cookie(s) set on {scheme}://{authority}/",
                    )
                )

            technologies = detect_technologies(headers, hop.body_prefix)
            if technologies:
                result.observations.append(
                    ObservationPayload(
                        kind="http_tech",
                        subject=f"{host}:{port}",
                        asset_key=host,
                        data={
                            "hostname": host,
                            "port": port,
                            "technologies": technologies,
                        },
                        confidence=Confidence.MEDIUM,
                        summary=(
                            "Technology hints: "
                            + ", ".join(
                                f"{t['product']}{('/' + t['version']) if t['version'] else ''}"
                                for t in technologies
                            )
                        ),
                    )
                )

            if hop.tls:
                result.observations.append(
                    ObservationPayload(
                        kind="http_tls",
                        subject=f"{host}:{port}",
                        asset_key=host,
                        data={
                            "hostname": host,
                            "port": port,
                            **hop.tls,
                        },
                        confidence=Confidence.HIGH,
                        summary=(
                            f"TLS {hop.tls.get('tls_version', 'unknown')} on {authority}, "
                            f"certificate expires {hop.tls.get('not_after', 'unknown')}"
                        ),
                    )
                )

            if self.discover_paths:
                self._probe_discovery_paths(request, base_url, port, host, result)

            # Only probe the first responsive port per scheme to bound scan time.
            break

    def _probe_discovery_paths(
        self, request: ScanRequest, base_url: str, port: int, host: str, result: CollectResult
    ) -> None:
        """Probe conventionally public metadata documents.

        Only GET, never a crawler, never authenticated. A 200 on a document that
        should be private is the interesting case, and the rule engine decides
        whether it matters.
        """
        for path in DISCOVERY_PATHS:
            if path == "/":
                continue
            hop = safe_get(
                base_url + path,
                timeout=min(request.timeout_seconds, 4.0),
                user_agent=request.user_agent,
                allow_redirects=False,
                validate_hook=self.validate_hook,
            )
            if hop.status_code is None:
                continue
            # Record 200s and 401/403 (proof the path exists behind auth) but
            # skip 404s and generic failures to keep observations meaningful.
            if hop.status_code == 404:
                continue

            body_markers: list[str] = []
            body_lower = hop.body_prefix.lower()
            if path == "/openapi.json" or path == "/swagger.json":
                if '"openapi"' in body_lower or '"swagger"' in body_lower:
                    body_markers.append("openapi_document")
            if path == "/.env" and ("=" in hop.body_prefix and "APP_" in hop.body_prefix.upper()):
                body_markers.append("dotenv_like_content")
            if path == "/.git/config" and "[core]" in body_lower:
                body_markers.append("git_config_content")
            if path == "/.well-known/openid-configuration" and "authorization_endpoint" in body_lower:
                body_markers.append("oidc_configuration")

            result.observations.append(
                ObservationPayload(
                    kind="http_discovery_path",
                    subject=f"{host}:{port}{path}",
                    asset_key=host,
                    data={
                        "hostname": host,
                        "port": port,
                        "path": path,
                        "status_code": hop.status_code,
                        "content_type": header_map(hop.headers).get("content-type"),
                        "body_prefix": hop.body_prefix[:4096],
                        "requires_auth": hop.status_code in (401, 403),
                        "body_markers": body_markers,
                    },
                    confidence=Confidence.HIGH,
                    summary=f"GET {path} -> HTTP {hop.status_code}",
                )
            )
