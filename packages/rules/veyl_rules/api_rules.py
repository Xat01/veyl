"""API detection rules.

Veyl identifies APIs from evidence: an OpenAPI or Swagger document that parses,
an OIDC discovery document, or a path that conventionally belongs to an API and
behaves like one. It does not guess that something is an API because the port
number looks right.

CORS receives the most careful treatment here, because the distinction between
"permissive" and "exploitable" is exactly where security tools most often
exaggerate. A wildcard origin with credentials disallowed is a very different
finding from a wildcard origin with credentials allowed.
"""

from __future__ import annotations

import json
import re

from veyl_api.enums import Confidence, RuleCategory, Severity
from veyl_rules.framework import RuleContext, RuleDefinition, RuleMatch

#: Paths whose presence indicates an API metadata document.
API_DOC_PATHS = {
    "/openapi.json": "OpenAPI",
    "/swagger.json": "Swagger",
    "/api-docs": "Swagger UI or OpenAPI",
    "/swagger-ui.html": "Swagger UI",
    "/swagger/index.html": "Swagger UI",
    "/.well-known/openid-configuration": "OpenID Connect discovery",
}

#: Markers that appear in operational endpoints exposed inline.
DIAGNOSTIC_MARKERS = (
    ("/actuator/health", "Spring Boot Actuator health endpoint"),
    ("/actuator/env", "Spring Boot Actuator environment endpoint"),
    ("/actuator", "Spring Boot Actuator"),
    ("/debug", "debug endpoint"),
    ("/metrics", "metrics endpoint"),
    ("/phpinfo.php", "PHP information page"),
)


def _discovery_observations(context: RuleContext) -> list[dict]:
    return context.of_kind("http_discovery_path")


def check_exposed_api_documentation(context: RuleContext) -> list[RuleMatch]:
    """An API description document is publicly retrievable and parseable."""
    matches: list[RuleMatch] = []
    for obs in _discovery_observations(context):
        path = obs.get("path")
        if path not in API_DOC_PATHS:
            continue
        if obs.get("status_code") != 200:
            continue
        if obs.get("requires_auth"):
            continue

        body = str(obs.get("body_prefix", ""))
        markers = obs.get("body_markers") or []

        # For OpenAPI specifically, require actual parseable structure rather
        # than trusting the path. A file called openapi.json that is not one is
        # not a finding.
        parsed_ok = False
        endpoint_count = 0
        doc_title = None
        if path in {"/openapi.json", "/swagger.json", "/.well-known/openid-configuration"}:
            try:
                document = json.loads(body)
                if isinstance(document, dict):
                    if path == "/.well-known/openid-configuration":
                        parsed_ok = "authorization_endpoint" in document
                    else:
                        parsed_ok = "paths" in document or "openapi" in document or "swagger" in document
                        paths = document.get("paths")
                        if isinstance(paths, dict):
                            endpoint_count = len(paths)
                        info = document.get("info")
                        if isinstance(info, dict):
                            doc_title = info.get("title")
            except (json.JSONDecodeError, ValueError):
                parsed_ok = bool(markers)

        if not parsed_ok:
            continue

        label = API_DOC_PATHS[path]
        detail = (
            f"{endpoint_count} documented path(s)" if endpoint_count else "document parsed"
        )
        matches.append(
            RuleMatch(
                subject_suffix=f"api-doc-{path}",
                summary=f"{label} documentation publicly retrievable at {path} ({detail})",
                detection_explanation=(
                    f"A GET to {path} returned HTTP 200 with a document that parsed as {label}. "
                    + (
                        f"The document declares {endpoint_count} paths"
                        + (f" and is titled {doc_title!r}" if doc_title else "")
                        + "."
                        if endpoint_count
                        else "The document contained the expected top-level structure."
                    )
                    + " Veyl recorded the first 4096 characters of the body as evidence."
                ),
                impact=(
                    f"An {label} document is a complete map of the API surface: every path, every "
                    f"method, and frequently the parameter names and authentication schemes. It "
                    f"removes the reconnaissance step entirely for an attacker and often reveals "
                    f"internal-only or newer endpoints that were not intended for public use. "
                    f"Whether this is a problem depends on whether the API is itself public: for "
                    f"a documented public API this is expected, and Veyl recommends confirming "
                    f"intent rather than treating it as a defect. Veyl has read the document only; "
                    f"it has not called any of the documented endpoints."
                ),
                evidence=[
                    {
                        "kind": "http_discovery_path",
                        "matcher": f"HTTP 200 at {path} parsing as {label}",
                        "detail": {
                            "path": path,
                            "status_code": obs.get("status_code"),
                            "content_type": obs.get("content_type"),
                            "endpoint_count": endpoint_count,
                            "document_title": doc_title,
                            "body_prefix": body[:4096],
                        },
                    }
                ],
                severity=Severity.MEDIUM if endpoint_count > 5 else Severity.LOW,
                confidence=Confidence.HIGH,
                risk_factors={
                    "api_issue": "documentation_exposure",
                    "documented_endpoints": endpoint_count,
                    "documentation_path": path,
                },
            )
        )
    return matches


def check_cors_misconfiguration(context: RuleContext) -> list[RuleMatch]:
    """CORS policy analysis, split by how dangerous the combination actually is."""
    matches: list[RuleMatch] = []
    for obs in context.of_kind("http_security_headers"):
        headers = obs.get("headers") or {}
        allow_origin = headers.get("access-control-allow-origin")
        allow_creds = headers.get("access-control-allow-credentials")

        if not allow_origin:
            continue

        origin_value = str(allow_origin).strip()
        creds_allowed = str(allow_creds).strip().lower() == "true" if allow_creds else False

        # Reflecting the request's Origin back dynamically cannot be detected
        # from a single unauthenticated request. We report only what we saw and
        # state the limitation rather than guessing.
        is_wildcard = origin_value == "*"
        is_specific = not is_wildcard and origin_value not in ("null",) and "," not in origin_value

        if is_wildcard and creds_allowed:
            severity = Severity.HIGH
            summary = "CORS wildcard origin combined with credentials"
            explanation = (
                "The response set Access-Control-Allow-Origin: * together with "
                "Access-Control-Allow-Credentials: true. This combination is rejected outright "
                "by browsers, which means the effective configuration is not what the headers "
                "appear to state."
            )
            impact = (
                "Because browsers refuse the wildcard-with-credentials combination, the practical "
                "effect is that credentialed cross-origin requests fail rather than succeed. The "
                "risk here is as much operational as security: the configuration does not do what "
                "it looks like it does. If it is later changed to reflect the request origin "
                "while credentials remain enabled, that would become a genuine vulnerability, so "
                "the configuration deserves correction rather than being left as it is."
            )
            risk = {"cors": "wildcard_with_credentials", "credentials_allowed": True}
        elif is_wildcard:
            severity = Severity.LOW
            summary = "CORS permits any origin (credentials not allowed)"
            explanation = (
                "The response set Access-Control-Allow-Origin: * without "
                "Access-Control-Allow-Credentials. Any origin may therefore read responses from "
                "this endpoint using a browser."
            )
            impact = (
                "A wildcard origin lets any website read responses that are returned without "
                "credentials. If this endpoint returns only public data, that is the intent of "
                "a public API and is not a defect. If it returns data that varies by "
                "unauthenticated context, such as an internal status page or an IP-scoped "
                "dashboard, the wildcard removes the isolation that assumed that context. Veyl "
                "cannot observe what the endpoint returns, so it reports the policy and its "
                "conditions rather than asserting an impact."
            )
            risk = {"cors": "wildcard", "credentials_allowed": False}
        elif origin_value == "null":
            severity = Severity.MEDIUM
            summary = "CORS allows the null origin"
            explanation = (
                "The response set Access-Control-Allow-Origin: null. The null origin is sent by "
                "sandboxed iframes, and by requests from file:// documents and some redirect "
                "patterns."
            )
            impact = (
                "Any party able to get content loaded in a sandboxed iframe receives the null "
                "origin, and this policy admits it. That makes the allow-list broader than it "
                "appears and is rarely intentional."
            )
            risk = {"cors": "null_origin"}
        elif is_specific and creds_allowed:
            severity = Severity.INFO
            summary = f"CORS allows a specific origin with credentials ({origin_value})"
            explanation = (
                f"The response set Access-Control-Allow-Origin: {origin_value} with "
                f"Access-Control-Allow-Credentials: true."
            )
            impact = (
                "This is the correct shape for a deliberate cross-origin integration. Veyl "
                "reports it for inventory so the allow-list can be reviewed periodically, and "
                "does not treat it as a defect. Note that Veyl sends no Origin header, so it "
                "cannot determine whether the server reflects arbitrary origins dynamically: "
                "that behaviour would not be visible without an authenticated cross-origin "
                "request."
            )
            risk = {"cors": "specific_origin_with_credentials", "origin": origin_value}
        else:
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"cors-port-{obs.get('port', 443)}",
                summary=summary,
                detection_explanation=(
                    explanation
                    + f" Veyl observed these headers on a request to "
                    f"{obs.get('scheme')}://{context.asset_key}:{obs.get('port', 443)}/ and "
                    f"recorded the full header set in the evidence."
                ),
                impact=impact,
                evidence=[
                    {
                        "kind": "http_security_headers",
                        "matcher": f"access-control-allow-origin == {origin_value!r}",
                        "detail": {
                            "port": obs.get("port"),
                            "scheme": obs.get("scheme"),
                            "access_control_allow_origin": origin_value,
                            "access_control_allow_credentials": allow_creds,
                            "access_control_allow_methods": headers.get("access-control-allow-methods"),
                            "all_headers": headers,
                        },
                    }
                ],
                severity=severity,
                confidence=Confidence.HIGH,
                risk_factors=risk,
            )
        )
    return matches


def check_exposed_diagnostic_endpoint(context: RuleContext) -> list[RuleMatch]:
    """Operational endpoints reachable without authentication."""
    matches: list[RuleMatch] = []
    for obs in _discovery_observations(context):
        path = obs.get("path")
        if obs.get("status_code") != 200:
            continue
        if obs.get("requires_auth"):
            continue
        label = next((l for p, l in DIAGNOSTIC_MARKERS if path == p), None)
        if label is None:
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"diagnostic-{path}",
                summary=f"{label} reachable without authentication",
                detection_explanation=(
                    f"A GET to {path} returned HTTP 200 without requiring authentication."
                ),
                impact=(
                    f"{label} typically exposes build information, environment properties, or "
                    f"runtime state. Spring Boot Actuator in particular can expose environment "
                    f"variables and, where the shutdown endpoint is enabled, allow a remote stop. "
                    f"Veyl confirmed reachability only; it did not read configuration values or "
                    f"invoke any management operation."
                ),
                evidence=[
                    {
                        "kind": "http_discovery_path",
                        "matcher": f"HTTP 200 without auth at {path}",
                        "detail": {
                            "path": path,
                            "status_code": obs.get("status_code"),
                            "content_type": obs.get("content_type"),
                            "body_prefix": str(obs.get("body_prefix", ""))[:1000],
                        },
                    }
                ],
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                risk_factors={"api_issue": "diagnostic_exposure", "path": path},
            )
        )
    return matches


def check_api_path_without_metadata(context: RuleContext) -> list[RuleMatch]:
    """An API-shaped path exists but no documentation or auth challenge was seen.

    Reported at INFO and only when there is at least one confirming signal.
    """
    matches: list[RuleMatch] = []
    has_doc = any(
        obs.get("path") in API_DOC_PATHS and obs.get("status_code") == 200
        for obs in _discovery_observations(context)
    )
    if not has_doc:
        return matches

    for obs in _discovery_observations(context):
        path = str(obs.get("path", ""))
        if not re.match(r"^/(api|v[0-9]+)(/|$)", path):
            continue
        matches.append(
            RuleMatch(
                subject_suffix=f"api-path-{path}",
                summary=f"API version prefix in use: {path}",
                detection_explanation=(
                    f"A discovered path {path!r} begins with an API version prefix, and API "
                    f"documentation was also found on this host."
                ),
                impact=(
                    "Recorded for inventory. The presence of a version prefix means multiple API "
                    "versions may be live concurrently, which matters for deprecation and for "
                    "tracking which version carries a given finding."
                ),
                evidence=[
                    {
                        "kind": "http_discovery_path",
                        "matcher": f"path {path!r} matches API version prefix pattern",
                        "detail": {"path": path, "status_code": obs.get("status_code")},
                    }
                ],
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                risk_factors={"api_issue": "version_prefix"},
            )
        )
    return matches


API_RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="VEYL-API-001",
        title="Potentially unsafe CORS configuration",
        category=RuleCategory.API,
        severity=Severity.LOW,
        default_confidence=Confidence.HIGH,
        description=(
            "The CORS policy permits any origin, the null origin, or combines a wildcard with "
            "credentials."
        ),
        detection=(
            "Fires on the specific CORS header combination observed. A wildcard origin with "
            "credentials allowed is HIGH; a null origin is MEDIUM; a bare wildcard without "
            "credentials is LOW; a specific origin with credentials is INFO and reported for "
            "inventory only."
        ),
        evidence_requirements=["http_security_headers"],
        remediation=(
            "Replace the wildcard with an explicit allow-list of origins that genuinely need "
            "browser access. Where credentials are required, never combine them with a wildcard "
            "or a reflected origin. Remove the null origin from any allow-list."
        ),
        check=check_cors_misconfiguration,
        requires=["http_security_headers"],
    ),
    RuleDefinition(
        rule_id="VEYL-API-002",
        title="API documentation publicly retrievable",
        category=RuleCategory.API,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description=(
            "An OpenAPI, Swagger or OIDC discovery document is publicly retrievable and parses "
            "as that document type."
        ),
        detection=(
            "Fires when a GET to a known documentation path returns HTTP 200 and the body parses "
            "as a valid document of that type. A file at the right path that does not parse is "
            "not reported."
        ),
        evidence_requirements=["http_discovery_path"],
        remediation=(
            "Confirm whether public API documentation is intended. If not, require "
            "authentication for the documentation path, or serve it only from an internal "
            "network. If it is intended, record that decision so the finding can be closed as "
            "accepted risk rather than re-triaged."
        ),
        check=check_exposed_api_documentation,
        requires=["http_discovery_path"],
    ),
    RuleDefinition(
        rule_id="VEYL-API-003",
        title="Operational endpoint reachable without authentication",
        category=RuleCategory.API,
        severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        description=(
            "A management or diagnostic endpoint such as Spring Boot Actuator or phpinfo is "
            "reachable without authentication."
        ),
        detection=(
            "Fires when a known operational path returns HTTP 200 without a 401 or 403 "
            "challenge."
        ),
        evidence_requirements=["http_discovery_path"],
        remediation=(
            "Restrict management endpoints to an internal network or a separate management port, "
            "and require authentication. Explicitly disable any management endpoint that is not "
            "needed, in particular env, heapdump and shutdown."
        ),
        check=check_exposed_diagnostic_endpoint,
        requires=["http_discovery_path"],
    ),
    RuleDefinition(
        rule_id="VEYL-API-004",
        title="API version prefix in active use",
        category=RuleCategory.API,
        severity=Severity.INFO,
        default_confidence=Confidence.MEDIUM,
        description="A discovered path uses an API version prefix alongside API documentation.",
        detection=(
            "Fires when a discovered path matches ^/(api|v[0-9]+)(/|$) and API documentation was "
            "also retrieved from the same host."
        ),
        evidence_requirements=["http_discovery_path"],
        remediation="No action required; recorded for inventory and change tracking.",
        check=check_api_path_without_metadata,
        requires=["http_discovery_path"],
    ),
]
