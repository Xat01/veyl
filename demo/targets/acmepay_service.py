"""Intentionally-exposed demo service used by the AcmePay scenario.

This is a deliberately misconfigured HTTP service. It exists so Veyl has
something *real* to discover and analyse during local demos: it presents an
outdated-looking server banner, omits security headers, leaks an OpenAPI
document, answers CORS permissively, and exposes an admin surface.

It is stdlib-only (no FastAPI/Flask) so it can run anywhere the project runs.
It performs no authentication, stores nothing, and must never be deployed to
any network reachable by anyone else.

Usage:
    python demo/targets/acmepay_service.py --port 8080
    python demo/targets/acmepay_service.py --port 8080 --profile day7
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Profiles
#
# The AcmePay story needs the same service to look different over time so that
# Veyl's change detection has something real to compare. "day1" is the
# well-configured baseline; "day5" introduces a new staging-ish surface; "day7"
# exposes an admin interface and drops a security header.
# ---------------------------------------------------------------------------

PROFILES = {
    "day1": {
        "server_banner": "nginx/1.18.0",
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        },
        "paths": {
            "/": "AcmePay payments API (day 1 baseline)",
            "/health": "ok",
        },
        "cors": None,
        "admin": False,
        "openapi": False,
        "server_version_in_banner": True,
    },
    "day5": {
        # A new internal-looking service appears on the same host, still
        # adequately configured but with a fresh surface area.
        "server_banner": "nginx/1.18.0",
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Security-Policy": "default-src 'self'",
        },
        "paths": {
            "/": "AcmePay payments API (day 5)",
            "/health": "ok",
            "/v2/reports": "v2 reporting service — internal use",
            "/openapi.json": None,  # filled in below
        },
        "cors": None,
        "admin": False,
        "openapi": True,
        "server_version_in_banner": True,
    },
    "day7": {
        # The regression: an admin interface is now reachable and the framing
        # protection has been dropped. This is what the demo is *about*.
        "server_banner": "nginx/1.18.0",
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            # X-Frame-Options deliberately removed
            "Content-Security-Policy": "default-src 'self'",
        },
        "paths": {
            "/": "AcmePay payments API (day 7)",
            "/health": "ok",
            "/v2/reports": "v2 reporting service — internal use",
            "/admin": "AcmePay administration console",
            "/admin/login": "Administrator sign-in",
            "/openapi.json": None,
        },
        "cors": {
            # Wildcard with credentials is the high-severity case. This is a
            # static response; Veyl cannot and does not claim it reflects
            # arbitrary origins.
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        "admin": True,
        "openapi": True,
        "server_version_in_banner": True,
    },
}

OPENAPI_DOCUMENT = {
    "openapi": "3.0.1",
    "info": {"title": "AcmePay Payments API", "version": "2.0.0"},
    "servers": [{"url": "/"}],
    "paths": {
        "/v2/payments": {
            "get": {"summary": "List payments", "security": []},
            "post": {"summary": "Create a payment", "security": []},
        },
        "/v2/refunds": {"post": {"summary": "Issue a refund", "security": []}},
        "/v2/reports/{report_id}": {
            "get": {
                "summary": "Fetch a report",
                "parameters": [
                    {"name": "report_id", "in": "path", "required": True,
                     "schema": {"type": "string"}}
                ],
            }
        },
    },
    "components": {"securitySchemes": {}},
}


class AcmePayHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    profile: dict = PROFILES["day1"]
    verbose: bool = True

    # -- helpers ----------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        for name, value in self.profile["headers"].items():
            self.send_header(name, value)
        cors = self.profile.get("cors")
        if cors:
            for name, value in cors.items():
                self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _log(self, note: str) -> None:
        if self.verbose:
            sys.stderr.write(f"  [target] {self.command} {self.path} -> {note}\n")

    # -- routing ----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._route()

    def do_HEAD(self) -> None:  # noqa: N802
        self._route()

    def do_POST(self) -> None:  # noqa: N802
        self._route()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._log("options (preflight)")
        self._send(204, b"")

    def _route(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        paths = self.profile["paths"]

        if path == "/openapi.json":
            if self.profile.get("openapi"):
                payload = json.dumps(OPENAPI_DOCUMENT, indent=2).encode()
                self._log("openapi document disclosed")
                self._send(200, payload, "application/json")
            else:
                self._log("not found")
                self._send(404, b"Not Found")
            return

        if path in paths:
            self._log("served")
            self._send(200, (paths[path] + "\n").encode())
            return

        if path.startswith("/admin") and self.profile.get("admin"):
            self._log("admin surface served")
            self._send(200, b"AcmePay administration console\n")
            return

        if path.startswith("/v2/"):
            self._log("api path")
            self._send(200, b'{"status":"accepted"}\n', "application/json")
            return

        self._log("not found")
        self._send(404, b"Not Found")

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        # Silence the default stderr access log; _log() covers what we need.
        return


def build_server(port: int, profile_name: str, tls: bool = False,
                 certfile: str | None = None, keyfile: str | None = None,
                 verbose: bool = True) -> ThreadingHTTPServer:
    profile = PROFILES[profile_name]
    handler = type(
        "BoundAcmePayHandler",
        (AcmePayHandler,),
        {"profile": profile, "verbose": verbose},
    )
    httpd = ThreadingHTTPServer(("0.0.0.0", port), handler)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if certfile and keyfile:
            context.load_cert_chain(certfile, keyfile)
        else:
            # Self-signed, generated on the fly — good enough for the TLS
            # rules to have something real to look at.
            context = _self_signed_context()
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd


def _self_signed_context() -> ssl.SSLContext:
    import datetime
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .sign(key, hashes.SHA256())
    )
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    cert_file.close()
    key_file.close()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file.name, key_file.name)
    return context


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AcmePay demo target service")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="day1")
    parser.add_argument("--tls", action="store_true", help="serve HTTPS with a self-signed cert")
    parser.add_argument("--cert", default=None)
    parser.add_argument("--key", default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    httpd = build_server(
        args.port, args.profile, tls=args.tls,
        certfile=args.cert, keyfile=args.key, verbose=not args.quiet,
    )
    scheme = "https" if args.tls else "http"
    print(f"AcmePay demo target listening on {scheme}://0.0.0.0:{args.port} "
          f"[profile={args.profile}]", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", flush=True)
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
