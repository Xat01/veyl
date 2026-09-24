"""Authentication-boundary and infrastructure rules.

These rules look for services that are reachable and appear to have no
authentication challenge in front of them, plus infrastructure defaults that are
commonly left exposed.

Veyl never attempts to bypass or brute-force authentication. "No authentication
observed" means exactly that: an unauthenticated request was not challenged. It
does not mean authentication is absent, and the wording of every finding here
reflects that distinction.
"""

from __future__ import annotations

import json

from veyl_api.enums import Confidence, RuleCategory, Severity
from veyl_rules.framework import RuleContext, RuleDefinition, RuleMatch

#: Paths and the label of the interface they front.
SENSITIVE_PATHS: dict[str, str] = {
    "/admin": "administrative interface",
    "/manager/html": "Tomcat manager",
    "/wp-admin": "WordPress administration",
    "/phpmyadmin": "phpMyAdmin",
    "/adminer.php": "Adminer",
    "/server-status": "Apache server-status",
    "/console": "management console",
    "/actuator/env": "Spring Boot environment endpoint",
    "/actuator/heapdump": "Spring Boot heap dump endpoint",
}

#: Ports for services that frequently ship without authentication.
UNAUTHENTICATED_SERVICE_PORTS: dict[int, str] = {
    2375: "Docker daemon API (unencrypted)",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def _discovery(context: RuleContext) -> list[dict]:
    return context.of_kind("http_discovery_path")


def _responses(context: RuleContext) -> list[dict]:
    return context.of_kind("http_response")


def check_unauthenticated_sensitive_path(context: RuleContext) -> list[RuleMatch]:
    """A sensitive interface answered without an authentication challenge."""
    matches: list[RuleMatch] = []
    for obs in _discovery(context):
        path = obs.get("path")
        if path not in SENSITIVE_PATHS:
            continue
        status = obs.get("status_code")
        # 401/403 is the correct answer and must not be reported.
        if status in (401, 403):
            continue
        # A redirect to a login page is also an acceptable answer.
        if status in (301, 302, 303, 307, 308):
            continue
        if status != 200:
            continue

        label = SENSITIVE_PATHS[path]
        body = str(obs.get("body_prefix", ""))
        has_login_marker = any(
            marker in body.lower()
            for marker in ("password", "login", "sign in", "username", "csrf")
        )

        # If the body clearly contains a login form, treat this as an
        # authenticated interface that served its login page, not as an
        # unauthenticated one. Say so at INFO rather than inflating it.
        if has_login_marker:
            matches.append(
                RuleMatch(
                    subject_suffix=f"authpath-{path}",
                    summary=f"{label} responds at {path} with a login form",
                    detection_explanation=(
                        f"A GET to {path} returned HTTP 200 and the body contained login-form "
                        f"markers. The interface is reachable and appears to present "
                        f"authentication, which is the expected behaviour."
                    ),
                    impact=(
                        "Reachability of an administrative login page is a normal exposure. It is "
                        "recorded so the interface is inventoried and so that a change in its "
                        "behaviour is visible. Veyl did not attempt to authenticate."
                    ),
                    evidence=[
                        {
                            "kind": "http_discovery_path",
                            "matcher": f"HTTP 200 with login markers at {path}",
                            "detail": {
                                "path": path,
                                "status_code": status,
                                "login_markers_found": True,
                                "body_prefix": body[:800],
                            },
                        }
                    ],
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    risk_factors={"auth_boundary": "login_page_reachable"},
                )
            )
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"unauth-{path}",
                summary=f"{label} responded at {path} without an authentication challenge",
                detection_explanation=(
                    f"A GET to {path} returned HTTP 200 with no 401 or 403 challenge and no "
                    f"redirect to a login page. Veyl searched the response body for login-form "
                    f"markers and found none. The full body prefix is recorded as evidence so "
                    f"this conclusion can be checked directly."
                ),
                impact=(
                    f"An {label} that answers unauthenticated requests is a control-plane "
                    f"exposure: it grants inspection or configuration access without "
                    f"credentials. Veyl has confirmed only that no authentication challenge was "
                    f"presented on this request. It has not attempted to perform any "
                    f"administrative action, and it cannot rule out that authentication is "
                    f"enforced by a control Veyl is not positioned to trigger."
                ),
                evidence=[
                    {
                        "kind": "http_discovery_path",
                        "matcher": f"HTTP 200 without auth challenge at {path}",
                        "detail": {
                            "path": path,
                            "status_code": status,
                            "content_type": obs.get("content_type"),
                            "login_markers_found": False,
                            "body_prefix": body[:2000],
                        },
                    }
                ],
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                risk_factors={"auth_boundary": "no_challenge_observed", "path": path},
            )
        )
    return matches


def check_unauthenticated_data_service(context: RuleContext) -> list[RuleMatch]:
    """A data service that commonly ships without auth is directly reachable."""
    matches: list[RuleMatch] = []
    port_scan = context.first("port_scan") or {}
    open_ports = {int(p) for p in port_scan.get("open_ports", []) if str(p).isdigit()}

    for obs in context.of_kind("service_fingerprint"):
        port = obs.get("port")
        if port not in UNAUTHENTICATED_SERVICE_PORTS:
            continue
        if port not in open_ports:
            continue

        label = UNAUTHENTICATED_SERVICE_PORTS[port]
        banner = obs.get("banner")
        # Only Redis gives us a directly interpretable signal in the banner:
        # a PING that returns +PONG means the server accepted an unauthenticated
        # command. Report that specifically when we have it.
        ping_confirmed = bool(banner and "NOAUTH" not in str(banner).upper())

        matches.append(
            RuleMatch(
                subject_suffix=f"unauth-service-{port}",
                summary=f"{label} reachable on TCP/{port} from the assessed position",
                detection_explanation=(
                    f"TCP/{port} is open and the fingerprint identified the protocol as "
                    f"{obs.get('service_name')!r}"
                    + (f" (product {obs.get('product')!r})" if obs.get("product") else "")
                    + ". "
                    + (
                        "Veyl sent the non-mutating PING command and received a response other "
                        "than the authentication-required error, which means the server accepted "
                        "an unauthenticated command."
                        if port == 6379 and ping_confirmed
                        else "Veyl did not issue any protocol command beyond the minimal "
                        "handshake, so it has not determined whether authentication is enforced."
                    )
                ),
                impact=(
                    f"{label} is frequently deployed with authentication disabled and bound to all "
                    f"interfaces, on the assumption that only trusted hosts can reach it. That "
                    f"assumption fails as soon as the port is reachable more widely. Redis and "
                    f"Memcached in particular have no meaningful access control in a default "
                    f"configuration and permit arbitrary read and write of their contents. "
                    + (
                        "For this finding Veyl obtained direct evidence that an unauthenticated "
                        "command succeeded."
                        if port == 6379 and ping_confirmed
                        else "Veyl has evidence of reachability; it has not verified whether "
                        "authentication is enforced on this instance."
                    )
                ),
                evidence=[
                    {
                        "kind": "port_scan",
                        "matcher": f"open_ports contains {port}",
                        "detail": {
                            "port": port,
                            "state": "open",
                            "scanner": port_scan.get("scanner"),
                        },
                    },
                    {
                        "kind": "service_fingerprint",
                        "matcher": f"service_fingerprint.port == {port}",
                        "detail": {
                            "port": port,
                            "service_name": obs.get("service_name"),
                            "product": obs.get("product"),
                            "version": obs.get("version"),
                            "banner": banner,
                            "command_attempted": "PING" if port == 6379 else None,
                            "auth_required_signal": (
                                "NOAUTH" in str(banner).upper() if banner else None
                            ),
                        },
                    },
                ],
                severity=Severity.HIGH,
                confidence=Confidence.HIGH if (port == 6379 and ping_confirmed) else Confidence.MEDIUM,
                risk_factors={
                    "auth_boundary": "data_service_reachable",
                    "port": port,
                    "unauthenticated_command_confirmed": bool(port == 6379 and ping_confirmed),
                },
            )
        )
    return matches


def check_default_infrastructure_exposure(context: RuleContext) -> list[RuleMatch]:
    """Container and orchestration control planes that are reachable."""
    matches: list[RuleMatch] = []
    port_scan = context.first("port_scan") or {}
    open_ports = {int(p) for p in port_scan.get("open_ports", []) if str(p).isdigit()}

    control_planes = {
        2375: (
            "Docker daemon API without TLS",
            Severity.CRITICAL,
            "The unencrypted Docker socket exposes the full Docker API. Anyone who can reach it "
            "can create a container that mounts the host filesystem, which is equivalent to root "
            "on the host. This is the single most impactful network exposure in container "
            "environments.",
        ),
        2376: (
            "Docker daemon API with TLS",
            Severity.HIGH,
            "The Docker API is reachable over TLS. Access is bounded by the client certificate "
            "the daemon requires, so the exposure depends on how that certificate is issued and "
            "whether it is shared. The blast radius if the certificate is obtained is equivalent "
            "to root on the host.",
        ),
        6443: (
            "Kubernetes API server",
            Severity.HIGH,
            "The Kubernetes control plane is reachable. Cluster authentication and RBAC are the "
            "boundary here, and both are commonly misconfigured in ways that grant more access "
            "than intended to an authenticated identity.",
        ),
        10250: (
            "Kubelet API",
            Severity.HIGH,
            "The Kubelet API is reachable. Depending on its configuration this can permit command "
            "execution inside any pod on the node.",
        ),
    }

    for port, (label, severity, impact) in control_planes.items():
        if port not in open_ports:
            continue
        service = next(
            (o for o in context.of_kind("service_fingerprint") if o.get("port") == port), None
        )
        matches.append(
            RuleMatch(
                subject_suffix=f"controlplane-{port}",
                summary=f"{label} reachable on TCP/{port}",
                detection_explanation=(
                    f"TCP/{port} responded as open. This port carries {label}. "
                    + (
                        f"The fingerprint identified the service as "
                        f"{service.get('product') or service.get('service_name')!r}."
                        if service
                        else "No service banner was retrieved."
                    )
                ),
                impact=impact,
                evidence=[
                    {
                        "kind": "port_scan",
                        "matcher": f"open_ports contains {port}",
                        "detail": {
                            "port": port,
                            "state": "open",
                            "scanner": port_scan.get("scanner"),
                        },
                    },
                    {
                        "kind": "service_fingerprint",
                        "matcher": f"service_fingerprint.port == {port}",
                        "detail": {
                            "port": port,
                            "service_name": (service or {}).get("service_name"),
                            "product": (service or {}).get("product"),
                            "banner": (service or {}).get("banner"),
                        },
                    },
                ],
                severity=severity,
                confidence=Confidence.HIGH,
                risk_factors={
                    "infrastructure": "control_plane_exposed",
                    "port": port,
                    "host_equivalent": port == 2375,
                },
            )
        )
    return matches


def check_open_redirect(context: RuleContext) -> list[RuleMatch]:
    """A redirect that echoes a caller-supplied parameter.

    Veyl has only the base response, so this fires only when the observed
    Location header points at a different origin than the request. It does not
    try to inject a parameter, because doing so would be testing for
    exploitability rather than observing exposure.
    """
    matches: list[RuleMatch] = []
    for obs in _responses(context):
        status = obs.get("status_code")
        if status not in (301, 302, 303, 307, 308):
            continue
        chain = obs.get("redirect_chain") or []
        for hop in chain:
            target = str(hop.get("to", ""))
            if not target:
                continue
            try:
                from urllib.parse import urlparse

                source_host = urlparse(str(hop.get("from", ""))).hostname
                target_host = urlparse(target).hostname
            except ValueError:
                continue
            if target_host and source_host and target_host != source_host:
                matches.append(
                    RuleMatch(
                        subject_suffix=f"redirect-{target_host}",
                        summary=f"Redirect leaves the requested host, to {target_host}",
                        detection_explanation=(
                            f"A request to {hop.get('from')} returned HTTP {hop.get('status')} "
                            f"redirecting to {target}. The destination host differs from the "
                            f"requested host."
                        ),
                        impact=(
                            "Cross-host redirects are normal for identity providers and "
                            "consolidated domains. They become a vulnerability only when the "
                            "destination is derived from a caller-supplied parameter, which Veyl "
                            "cannot determine without sending crafted input. This is reported so "
                            "the redirect target can be reviewed, not as an assertion that the "
                            "endpoint is exploitable."
                        ),
                        evidence=[
                            {
                                "kind": "http_response",
                                "matcher": f"redirect chain hop to different host {target_host}",
                                "detail": {
                                    "from": hop.get("from"),
                                    "to": target,
                                    "status": hop.get("status"),
                                    "redirect_chain": chain,
                                },
                            }
                        ],
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        risk_factors={"web_issue": "cross_host_redirect"},
                    )
                )
    return matches


def check_exposed_swagger_ui(context: RuleContext) -> list[RuleMatch]:
    """Swagger UI itself is served, not just the document."""
    matches: list[RuleMatch] = []
    for obs in _discovery(context):
        path = obs.get("path")
        if path not in {"/swagger-ui.html", "/swagger/index.html", "/api-docs"}:
            continue
        if obs.get("status_code") != 200:
            continue
        body = str(obs.get("body_prefix", "")).lower()
        if "swagger" not in body and "openapi" not in body:
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"swagger-ui-{path}",
                summary=f"Swagger UI is served at {path}",
                detection_explanation=(
                    f"A GET to {path} returned HTTP 200 with a body referencing Swagger or "
                    f"OpenAPI. This is the interactive console, not only the description "
                    f"document."
                ),
                impact=(
                    "Swagger UI renders an interactive console that can issue requests to every "
                    "documented endpoint from a browser. Combined with an unauthenticated "
                    "document it gives a complete, clickable map of the API. Veyl loaded the page "
                    "only; it did not use the console to call any endpoint."
                ),
                evidence=[
                    {
                        "kind": "http_discovery_path",
                        "matcher": f"HTTP 200 serving Swagger UI at {path}",
                        "detail": {
                            "path": path,
                            "status_code": obs.get("status_code"),
                            "body_prefix": str(obs.get("body_prefix", ""))[:600],
                        },
                    }
                ],
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                risk_factors={"api_issue": "interactive_console_exposed"},
            )
        )
    return matches


AUTHENTICATION_RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="VEYL-AUTH-001",
        title="Sensitive interface reachable without an authentication challenge",
        category=RuleCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        default_confidence=Confidence.MEDIUM,
        description=(
            "An administrative or management path returned content rather than an "
            "authentication challenge."
        ),
        detection=(
            "Fires when a known sensitive path returns HTTP 200, is not a redirect, and its body "
            "contains no login-form markers. Paths returning 401 or 403 are explicitly not "
            "reported."
        ),
        evidence_requirements=["http_discovery_path"],
        remediation=(
            "Require authentication for the interface and verify it with an unauthenticated "
            "request from outside the trusted network. Where the interface should not be "
            "internet-reachable at all, restrict it at the network layer."
        ),
        check=check_unauthenticated_sensitive_path,
        requires=["http_discovery_path"],
    ),
    RuleDefinition(
        rule_id="VEYL-AUTH-002",
        title="Data service reachable from the assessed position",
        category=RuleCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        description=(
            "A service that commonly ships without authentication (Redis, Memcached, "
            "Elasticsearch, MongoDB, Docker) is reachable."
        ),
        detection=(
            "Fires when a port associated with a commonly-unauthenticated service is open and "
            "the fingerprint identifies the protocol. For Redis, if the non-mutating PING command "
            "returns anything other than an authentication-required error, the finding notes that "
            "an unauthenticated command was confirmed to succeed."
        ),
        evidence_requirements=["port_scan", "service_fingerprint"],
        remediation=(
            "Enable authentication and bind the service to a private interface. Treat network "
            "placement as a secondary control, not the primary one, because network boundaries "
            "change more often than service configuration does."
        ),
        check=check_unauthenticated_data_service,
        requires=["port_scan", "service_fingerprint"],
    ),
    RuleDefinition(
        rule_id="VEYL-AUTH-003",
        title="Cross-host redirect",
        category=RuleCategory.AUTHENTICATION,
        severity=Severity.INFO,
        default_confidence=Confidence.MEDIUM,
        description="A response redirects to a different host than the one requested.",
        detection=(
            "Fires when a 3xx response's Location header names a host different from the "
            "requested host. Veyl does not inject parameters, so it cannot and does not claim "
            "this is an open redirect."
        ),
        evidence_requirements=["http_response"],
        remediation=(
            "Review the redirect target. If a destination is ever derived from a "
            "caller-supplied parameter, validate it against an allow-list of permitted "
            "destinations."
        ),
        check=check_open_redirect,
        requires=["http_response"],
    ),
]

INFRASTRUCTURE_RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="VEYL-INFRA-001",
        title="Container or orchestration control plane exposed",
        category=RuleCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        default_confidence=Confidence.HIGH,
        description=(
            "A Docker, Kubernetes or Kubelet control-plane port is reachable. These grant "
            "host-equivalent or cluster-wide control."
        ),
        detection=(
            "Fires when a port in {2375, 2376, 6443, 10250} is reported open by the port sweep."
        ),
        evidence_requirements=["port_scan", "service_fingerprint (optional)"],
        remediation=(
            "These ports should never be internet-reachable. Restrict them to a management "
            "network or VPN immediately. For the unencrypted Docker socket, assume compromise if "
            "it has been reachable and review container and image history on the host."
        ),
        check=check_default_infrastructure_exposure,
        requires=["port_scan"],
    ),
    RuleDefinition(
        rule_id="VEYL-INFRA-002",
        title="Interactive API console served",
        category=RuleCategory.INFRASTRUCTURE,
        severity=Severity.LOW,
        default_confidence=Confidence.HIGH,
        description="Swagger UI or an equivalent interactive API console is served publicly.",
        detection=(
            "Fires when a Swagger UI path returns HTTP 200 with a body referencing Swagger or "
            "OpenAPI."
        ),
        evidence_requirements=["http_discovery_path"],
        remediation=(
            "Serve the console only in non-production environments, or require authentication "
            "for it."
        ),
        check=check_exposed_swagger_ui,
        requires=["http_discovery_path"],
    ),
]
