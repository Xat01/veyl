"""Web application detection rules.

The discipline here matters more than in any other category, because missing
security headers are the most over-reported class of finding in the industry.
Every rule in this file states what the header does and what its absence means
in practice, distinguishes absence from misconfiguration, and refuses to
describe an absent header as exploitable on its own.

Where a missing control is only meaningful in combination — CSP without inline
script evaluation, HSTS without HTTPS — the rule says so explicitly.
"""

from __future__ import annotations

from veyl_api.enums import Confidence, RuleCategory, Severity
from veyl_rules.framework import RuleContext, RuleDefinition, RuleMatch


def _header_observations(context: RuleContext) -> list[dict]:
    return context.of_kind("http_security_headers")


def _has_header(obs: dict, name: str) -> bool:
    headers = obs.get("headers") or {}
    value = headers.get(name)
    return bool(value and str(value).strip())


def _header_value(obs: dict, name: str) -> str | None:
    headers = obs.get("headers") or {}
    value = headers.get(name)
    return str(value) if value else None


def _response_observations(context: RuleContext) -> list[dict]:
    return context.of_kind("http_response")


def _evidence_headers(obs: dict, matcher: str, name: str) -> dict:
    return {
        "kind": "http_security_headers",
        "matcher": matcher,
        "detail": {
            "port": obs.get("port"),
            "scheme": obs.get("scheme"),
            "header": name,
            "value": _header_value(obs, name),
            "all_headers": obs.get("headers"),
            "present": obs.get("present"),
            "absent": obs.get("absent"),
        },
    }


def check_missing_hsts(context: RuleContext) -> list[RuleMatch]:
    """HSTS is only meaningful over HTTPS, so HTTP-only services are exempt."""
    matches: list[RuleMatch] = []
    for obs in _header_observations(context):
        if obs.get("scheme") != "https":
            continue
        if _has_header(obs, "strict-transport-security"):
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary="HTTP Strict Transport Security is not set",
                detection_explanation=(
                    f"Veyl requested https://{context.asset_key}:{obs.get('port', 443)}/ and "
                    f"received a response. The response did not include a "
                    f"Strict-Transport-Security header. Veyl examined the response headers it "
                    f"actually received; the full set is recorded in the evidence."
                ),
                impact=(
                    "Without HSTS, a browser will attempt plain HTTP for this host on a first "
                    "visit or after a cache expiry, which gives a network attacker a window to "
                    "intercept the request and either read it or redirect it. HSTS closes that "
                    "window by instructing the browser to refuse HTTP for the host for a stated "
                    "duration. Its absence is a real, if narrow, exposure: it requires an "
                    "attacker positioned on the network path, and it does not by itself "
                    "compromise a connection that is already using HTTPS."
                ),
                evidence=[
                    _evidence_headers(
                        obs,
                        "strict-transport-security absent from an HTTPS response",
                        "strict-transport-security",
                    )
                ],
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                risk_factors={"web_control": "hsts", "transport_downgrade_window": True},
            )
        )
    return matches


def check_hsts_too_short(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in _header_observations(context):
        if obs.get("scheme") != "https":
            continue
        raw = _header_value(obs, "strict-transport-security")
        if not raw:
            continue
        lowered = raw.lower()
        if "preload" in lowered:
            continue

        import re

        match = re.search(r"max-age\s*=\s*(\d+)", lowered)
        if not match:
            # Header present but unparseable: report the observation, not a guess.
            matches.append(
                RuleMatch(
                    subject_suffix=f"port-{obs.get('port', 443)}",
                    summary="HSTS header present but max-age could not be parsed",
                    detection_explanation=(
                        f"The response included Strict-Transport-Security: {raw!r}. Veyl could "
                        f"not find a max-age directive in that value."
                    ),
                    impact=(
                        "A malformed HSTS header may be ignored entirely by browsers, which "
                        "means the protection HSTS was intended to provide is not in effect."
                    ),
                    evidence=[
                        _evidence_headers(obs, f"HSTS value unparseable: {raw!r}", "strict-transport-security")
                    ],
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    risk_factors={"web_control": "hsts"},
                )
            )
            continue

        max_age = int(match.group(1))
        if max_age >= 15_552_000:  # six months
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary=f"HSTS max-age is {max_age} seconds ({max_age // 86400} days)",
                detection_explanation=(
                    f"The response included Strict-Transport-Security with max-age={max_age}. "
                    f"Veyl compares this against a six-month (15552000 second) baseline. The "
                    f"complete header value was {raw!r}."
                ),
                impact=(
                    "A short max-age limits how long a browser enforces HTTPS-only for this host. "
                    "Between the expiry of one max-age window and the next visit, the downgrade "
                    "window that HSTS exists to close is open again."
                ),
                evidence=[
                    _evidence_headers(obs, f"max-age={max_age} < 15552000", "strict-transport-security")
                ],
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                risk_factors={"web_control": "hsts", "hsts_max_age": max_age},
            )
        )
    return matches


def check_missing_csp(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in _header_observations(context):
        if _has_header(obs, "content-security-policy") or _has_header(
            obs, "content-security-policy-report-only"
        ):
            continue
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary="Content Security Policy is not set",
                detection_explanation=(
                    "The response did not include a Content-Security-Policy header, and no "
                    "report-only policy was present either. Veyl examined the response headers it "
                    "received."
                ),
                impact=(
                    "CSP is a defence-in-depth control against script injection. Its absence does "
                    "not mean the application is vulnerable to cross-site scripting; it means "
                    "that if an injection flaw exists anywhere in the application, the browser "
                    "has no instruction to refuse the injected script. Applications that render "
                    "only static content and reflect no user input gain very little from CSP, "
                    "and Veyl cannot see the application logic from outside, so it reports the "
                    "missing control at LOW severity rather than asserting exploitability."
                ),
                evidence=[
                    _evidence_headers(obs, "content-security-policy absent", "content-security-policy")
                ],
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                risk_factors={"web_control": "csp"},
            )
        )
    return matches


def check_weak_csp(context: RuleContext) -> list[RuleMatch]:
    """CSP present but containing directives that defeat it."""
    matches: list[RuleMatch] = []
    for obs in _header_observations(context):
        raw = _header_value(obs, "content-security-policy")
        if not raw:
            continue
        lowered = raw.lower()

        problems: list[str] = []
        if "'unsafe-inline'" in lowered:
            problems.append("'unsafe-inline' permits inline script and style, which is the exact "
                            "vector CSP exists to block")
        if "'unsafe-eval'" in lowered:
            problems.append("'unsafe-eval' permits dynamic code evaluation via eval() and "
                            "Function()")
        if "script-src" in lowered and (
            "http:" in lowered.split("script-src", 1)[1].split(";")[0]
        ):
            problems.append("script-src permits loading over plain HTTP, which an active attacker "
                            "can substitute")
        if "*" in lowered.split("script-src", 1)[1].split(";")[0] if "script-src" in lowered else False:
            problems.append("script-src uses a wildcard, which permits any origin")

        if not problems:
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary=f"CSP contains permissive directives ({len(problems)} issue(s))",
                detection_explanation=(
                    f"The response included Content-Security-Policy: {raw!r}. Veyl flagged the "
                    f"following directives as reducing the policy's effectiveness: "
                    + "; ".join(problems)
                    + "."
                ),
                impact=(
                    "A permissive policy provides much less protection than the presence of the "
                    "header suggests. A reader who sees 'CSP is set' may reasonably believe "
                    "injected script would be blocked, when in fact 'unsafe-inline' allows it."
                ),
                evidence=[
                    _evidence_headers(obs, "CSP contains permissive directive(s)", "content-security-policy")
                ],
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                risk_factors={"web_control": "csp", "csp_problems": problems},
            )
        )
    return matches


def check_missing_x_content_type_options(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in _header_observations(context):
        if _has_header(obs, "x-content-type-options"):
            continue
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary="X-Content-Type-Options: nosniff is not set",
                detection_explanation=(
                    "The response did not include an X-Content-Type-Options header, so browsers "
                    "may MIME-sniff response bodies rather than honouring the declared "
                    "Content-Type."
                ),
                impact=(
                    "MIME sniffing allows a browser to interpret a response as a type other than "
                    "the one declared. The classic case is an uploaded file served back and "
                    "sniffed as HTML, which turns a file upload into stored script execution. "
                    "This requires a file upload or similar content-serving path to be present, "
                    "which Veyl cannot observe from outside, so the finding is informational "
                    "rather than an assertion of exploitability."
                ),
                evidence=[
                    _evidence_headers(obs, "x-content-type-options absent", "x-content-type-options")
                ],
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                risk_factors={"web_control": "nosniff"},
            )
        )
    return matches


def check_missing_frame_protection(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in _header_observations(context):
        xfo = _header_value(obs, "x-frame-options")
        csp = _header_value(obs, "content-security-policy") or ""
        if xfo:
            continue
        if "frame-ancestors" in csp.lower():
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary="No clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
                detection_explanation=(
                    "The response set neither X-Frame-Options nor a CSP frame-ancestors directive, "
                    "and no frame-ancestors directive was present in the CSP."
                ),
                impact=(
                    "Without frame restrictions the page can be embedded in an attacker-controlled "
                    "frame and overlaid with deceptive UI to capture clicks. Whether this matters "
                    "depends on whether the page performs state-changing actions that a single "
                    "click can trigger, which Veyl cannot determine externally."
                ),
                evidence=[
                    _evidence_headers(obs, "x-frame-options and csp frame-ancestors both absent", "x-frame-options"),
                    {
                        "kind": "http_security_headers",
                        "matcher": "content-security-policy frame-ancestors absent",
                        "detail": {
                            "content_security_policy": csp or None,
                            "frame_ancestors_present": "frame-ancestors" in csp.lower(),
                        },
                    },
                ],
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                risk_factors={"web_control": "frame_protection"},
            )
        )
    return matches


def check_missing_referrer_policy(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in _header_observations(context):
        if _has_header(obs, "referrer-policy"):
            continue
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary="Referrer-Policy is not set",
                detection_explanation=(
                    "The response did not include a Referrer-Policy header, so browsers apply "
                    "their own default when sending the Referer header to other origins."
                ),
                impact=(
                    "Where URLs contain identifiers, tokens in query strings, or internal path "
                    "structure, the default behaviour can disclose those to third-party sites "
                    "that the page links to. The severity depends entirely on what appears in "
                    "the application's URLs, which Veyl cannot observe from outside."
                ),
                evidence=[
                    _evidence_headers(obs, "referrer-policy absent", "referrer-policy")
                ],
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                risk_factors={"web_control": "referrer_policy"},
            )
        )
    return matches


def check_server_disclosure(context: RuleContext) -> list[RuleMatch]:
    """Version disclosure in banner headers."""
    matches: list[RuleMatch] = []
    for obs in _header_observations(context):
        for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            value = _header_value(obs, header)
            if not value:
                continue
            # Only report when the value carries something version-like.
            has_version = any(ch.isdigit() for ch in value) and any(
                ch in value for ch in ("/", ".", "-")
            )
            if not has_version:
                continue

            matches.append(
                RuleMatch(
                    subject_suffix=f"{header}-port-{obs.get('port', 443)}",
                    summary=f"Version disclosed via {header}: {value}",
                    detection_explanation=(
                        f"The response included {header}: {value!r}. This value discloses both "
                        f"the product and its version to any client that asks."
                    ),
                    impact=(
                        "Version disclosure lets an attacker skip reconnaissance and go directly "
                        "to known issues for that specific version. It does not create a "
                        "vulnerability, and where the product is unpatched the banner is not the "
                        "real problem. It is worth removing because it costs nothing and removes "
                        "a free shortcut."
                    ),
                    evidence=[
                        _evidence_headers(
                            obs, f"{header} present and version-like: {value!r}", header
                        )
                    ],
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    risk_factors={"web_control": "banner_disclosure", "header": header},
                )
            )
    return matches


def check_cookie_flags(context: RuleContext) -> list[RuleMatch]:
    """Cookies missing HttpOnly, Secure, or SameSite."""
    matches: list[RuleMatch] = []
    for obs in context.of_kind("http_cookies"):
        scheme = "https" if obs.get("port") in (443, 8443) else "http"
        for cookie in obs.get("cookies", []):
            problems: list[str] = []
            if not cookie.get("httponly"):
                problems.append("HttpOnly")
            if scheme == "https" and not cookie.get("secure"):
                problems.append("Secure")
            if not cookie.get("samesite"):
                problems.append("SameSite")
            if not problems:
                continue

            matches.append(
                RuleMatch(
                    subject_suffix=f"cookie-{cookie.get('name')}-port-{obs.get('port', 443)}",
                    summary=f"Cookie {cookie.get('name')!r} missing flag(s): {', '.join(problems)}",
                    detection_explanation=(
                        f"Veyl parsed the Set-Cookie header from "
                        f"{scheme}://{context.asset_key}:{obs.get('port', 443)}/ and observed the "
                        f"cookie {cookie.get('name')!r} with HttpOnly="
                        f"{cookie.get('httponly')}, Secure={cookie.get('secure')}, "
                        f"SameSite={cookie.get('samesite')}."
                    ),
                    impact=(
                        "HttpOnly withholds the cookie from JavaScript, which limits the damage "
                        "from a script-injection flaw. Secure prevents it being sent over plain "
                        "HTTP, which matters because the transport downgrade window is real. "
                        "SameSite restricts cross-site sending, which is the primary modern "
                        "defence against cross-site request forgery. Which of these matters most "
                        "depends on what the cookie holds, and Veyl cannot read the application "
                        "to find out; it reports what the flags are."
                    ),
                    evidence=[
                        {
                            "kind": "http_cookies",
                            "matcher": f"cookie {cookie.get('name')!r} missing {problems}",
                            "detail": {
                                "port": obs.get("port"),
                                "scheme": scheme,
                                "cookie": cookie,
                                "missing_flags": problems,
                            },
                        }
                    ],
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    risk_factors={"web_control": "cookie_flags", "missing_flags": problems},
                )
            )
    return matches


def check_directory_listing(context: RuleContext) -> list[RuleMatch]:
    """A directory index that exposes files."""
    matches: list[RuleMatch] = []
    for obs in context.of_kind("http_discovery_path"):
        body = str(obs.get("body_prefix", "")).lower()
        if "index of /" not in body and "<title>directory listing for" not in body:
            continue
        matches.append(
            RuleMatch(
                subject_suffix=f"path-{obs.get('path')}",
                summary=f"Directory listing enabled at {obs.get('path')}",
                detection_explanation=(
                    f"A GET to {obs.get('path')} returned HTTP {obs.get('status_code')} with a "
                    f"body containing directory-index markers. Veyl records the body prefix in "
                    f"the evidence so the observation can be checked directly."
                ),
                impact=(
                    "A directory index discloses the file names in that directory. Whether that "
                    "matters depends on what the directory contains: a backup archive or a "
                    "configuration export in a browsable directory is a direct disclosure, while "
                    "an intentionally published asset directory is not."
                ),
                evidence=[
                    {
                        "kind": "http_discovery_path",
                        "matcher": f"body contains directory index marker at {obs.get('path')}",
                        "detail": {
                            "path": obs.get("path"),
                            "status_code": obs.get("status_code"),
                            "body_prefix": str(obs.get("body_prefix", ""))[:1000],
                        },
                    }
                ],
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                risk_factors={"web_issue": "directory_listing"},
            )
        )
    return matches


def check_public_config_exposure(context: RuleContext) -> list[RuleMatch]:
    """A file that should never be public returned actual content."""
    matches: list[RuleMatch] = []
    sensitive_paths = {
        "/.env": "environment file",
        "/.git/config": "Git repository configuration",
    }
    for obs in context.of_kind("http_discovery_path"):
        path = obs.get("path")
        if path not in sensitive_paths:
            continue
        if obs.get("status_code") != 200:
            continue
        markers = obs.get("body_markers") or []
        if not markers:
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"path-{path}",
                summary=f"{sensitive_paths[path]} is publicly retrievable at {path}",
                detection_explanation=(
                    f"A GET to {path} returned HTTP 200 and the body matched the signature for "
                    f"a {sensitive_paths[path]} ({', '.join(markers)}). Veyl records the first "
                    f"1000 characters of the body so the claim can be verified directly. Veyl "
                    f"does not extract or store credential values."
                ),
                impact=(
                    f"A publicly readable {sensitive_paths[path]} commonly contains connection "
                    f"strings, API keys, and third-party credentials. Anyone who can reach this "
                    f"URL can read them. This is one of the few findings where the exposure is "
                    f"self-evident and the remediation is unambiguous."
                ),
                evidence=[
                    {
                        "kind": "http_discovery_path",
                        "matcher": f"HTTP 200 on {path} with content markers {markers}",
                        "detail": {
                            "path": path,
                            "status_code": obs.get("status_code"),
                            "content_type": obs.get("content_type"),
                            "body_markers": markers,
                            "body_prefix": str(obs.get("body_prefix", ""))[:1000],
                        },
                    }
                ],
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                risk_factors={"web_issue": "config_exposure", "path": path},
            )
        )
    return matches


def check_http_error_disclosure(context: RuleContext) -> list[RuleMatch]:
    """Server error responses that leak stack traces or framework detail."""
    matches: list[RuleMatch] = []
    markers = (
        ("traceback (most recent call last)", "a Python traceback"),
        ("java.lang.", "a Java stack trace"),
        ("at org.", "a Java stack trace"),
        ("stack trace:", "a .NET stack trace"),
        ("system.nullreferenceexception", "a .NET exception"),
        ("<b>fatal error</b>", "a PHP fatal error with file path"),
        ("warning: mysql", "a database error message"),
        ("sqlstate[", "a database error message"),
    )
    for obs in _response_observations(context):
        status = obs.get("status_code") or 0
        if status < 500:
            continue
        body = str(obs.get("body_prefix", "")).lower()
        hit = next(((m, label) for m, label in markers if m in body), None)
        if hit is None:
            continue

        marker, label = hit
        matches.append(
            RuleMatch(
                subject_suffix=f"status-{status}",
                summary=f"Error response discloses {label}",
                detection_explanation=(
                    f"A request returned HTTP {status} and the response body contained the "
                    f"signature for {label} (matched {marker!r})."
                ),
                impact=(
                    "Stack traces and database errors disclose internal file paths, library "
                    "versions, query structure and sometimes fragments of data. This is "
                    "high-value reconnaissance that reduces the effort required for a follow-up "
                    "attack, and it often appears only on specific error paths, which means it "
                    "can be triggered deliberately."
                ),
                evidence=[
                    {
                        "kind": "http_response",
                        "matcher": f"status >= 500 and body matched {marker!r}",
                        "detail": {
                            "status_code": status,
                            "url": obs.get("url"),
                            "matched_marker": marker,
                            "body_prefix": str(obs.get("body_prefix", ""))[:1500],
                        },
                    }
                ],
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                risk_factors={"web_issue": "error_disclosure"},
            )
        )
    return matches


WEB_RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="VEYL-WEB-001",
        title="Missing HTTP Strict Transport Security",
        category=RuleCategory.WEB,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description="An HTTPS service does not instruct browsers to use HTTPS only.",
        detection=(
            "Fires when an HTTPS response does not include a Strict-Transport-Security header. "
            "HTTP-only services are not flagged because HSTS has no effect without HTTPS."
        ),
        evidence_requirements=["http_security_headers"],
        remediation=(
            "Add Strict-Transport-Security with a max-age of at least six months, and add the "
            "includeSubDomains directive once every subdomain is confirmed HTTPS-capable. "
            "Consider preload only after includeSubDomains has been stable for some time."
        ),
        check=check_missing_hsts,
        requires=["http_security_headers"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-002",
        title="HSTS max-age below recommended baseline",
        category=RuleCategory.WEB,
        severity=Severity.LOW,
        default_confidence=Confidence.HIGH,
        description="HSTS is present with a max-age shorter than six months.",
        detection=(
            "Fires when Strict-Transport-Security is present, does not include preload, and its "
            "max-age directive is below 15552000 seconds."
        ),
        evidence_requirements=["http_security_headers"],
        remediation="Raise the max-age to at least six months, then to one year or more.",
        check=check_hsts_too_short,
        requires=["http_security_headers"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-003",
        title="Missing Content Security Policy",
        category=RuleCategory.WEB,
        severity=Severity.LOW,
        default_confidence=Confidence.HIGH,
        description="No Content-Security-Policy header (enforcing or report-only) is set.",
        detection=(
            "Fires when neither content-security-policy nor content-security-policy-report-only "
            "is present in the response headers."
        ),
        evidence_requirements=["http_security_headers"],
        remediation=(
            "Deploy a Content-Security-Policy, starting in report-only mode to identify the "
            "directives the application actually needs, then enforce it. In particular avoid "
            "'unsafe-inline' and 'unsafe-eval'."
        ),
        check=check_missing_csp,
        requires=["http_security_headers"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-004",
        title="Permissive Content Security Policy",
        category=RuleCategory.WEB,
        severity=Severity.LOW,
        default_confidence=Confidence.HIGH,
        description="A CSP is present but contains directives that defeat its purpose.",
        detection=(
            "Fires when the CSP includes 'unsafe-inline', 'unsafe-eval', a wildcard script-src, "
            "or permits script loading over plain HTTP."
        ),
        evidence_requirements=["http_security_headers"],
        remediation=(
            "Remove 'unsafe-inline' and 'unsafe-eval' and replace inline script with external "
            "files or nonce-based loading. Restrict script-src to specific origins."
        ),
        check=check_weak_csp,
        requires=["http_security_headers"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-005",
        title="Missing X-Content-Type-Options",
        category=RuleCategory.WEB,
        severity=Severity.INFO,
        default_confidence=Confidence.HIGH,
        description="MIME sniffing is not disabled.",
        detection="Fires when the response does not include X-Content-Type-Options: nosniff.",
        evidence_requirements=["http_security_headers"],
        remediation="Set X-Content-Type-Options: nosniff on all responses.",
        check=check_missing_x_content_type_options,
        requires=["http_security_headers"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-006",
        title="No clickjacking protection",
        category=RuleCategory.WEB,
        severity=Severity.LOW,
        default_confidence=Confidence.HIGH,
        description="Neither X-Frame-Options nor CSP frame-ancestors restricts framing.",
        detection=(
            "Fires when X-Frame-Options is absent and no frame-ancestors directive appears in "
            "the Content-Security-Policy."
        ),
        evidence_requirements=["http_security_headers"],
        remediation=(
            "Set a CSP frame-ancestors directive naming the permitted embedding origins, which "
            "supersedes X-Frame-Options. Use X-Frame-Options: DENY or SAMEORIGIN where CSP is "
            "not yet deployable."
        ),
        check=check_missing_frame_protection,
        requires=["http_security_headers"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-007",
        title="Missing Referrer-Policy",
        category=RuleCategory.WEB,
        severity=Severity.INFO,
        default_confidence=Confidence.HIGH,
        description="Referrer-Policy is not set, so the browser default applies.",
        detection="Fires when the response does not include a Referrer-Policy header.",
        evidence_requirements=["http_security_headers"],
        remediation=(
            "Set Referrer-Policy: strict-origin-when-cross-origin, or no-referrer where the "
            "application does not require referrer information."
        ),
        check=check_missing_referrer_policy,
        requires=["http_security_headers"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-008",
        title="Server version disclosed in response headers",
        category=RuleCategory.WEB,
        severity=Severity.INFO,
        default_confidence=Confidence.HIGH,
        description="A response header discloses the product and version of the server component.",
        detection=(
            "Fires when Server, X-Powered-By, X-AspNet-Version or X-Generator is present and "
            "carries a version-like value."
        ),
        evidence_requirements=["http_security_headers"],
        remediation=(
            "Configure the server to suppress or genericise banner headers. Treat this as "
            "hardening, not as remediation of a vulnerability."
        ),
        check=check_server_disclosure,
        requires=["http_security_headers"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-009",
        title="Cookie set without protective flags",
        category=RuleCategory.WEB,
        severity=Severity.LOW,
        default_confidence=Confidence.HIGH,
        description="A cookie is missing HttpOnly, Secure, or SameSite.",
        detection=(
            "Fires per cookie for each missing flag. Secure is only required when the cookie was "
            "set over HTTPS. SameSite is reported when entirely absent."
        ),
        evidence_requirements=["http_cookies"],
        remediation=(
            "Set HttpOnly and Secure on session cookies, and set SameSite=Lax or Strict unless "
            "the cookie must be sent in a cross-site context, in which case use None together "
            "with Secure."
        ),
        check=check_cookie_flags,
        requires=["http_cookies"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-010",
        title="Directory listing enabled",
        category=RuleCategory.WEB,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description="A requested path returned a browsable directory index.",
        detection=(
            "Fires when a probed path returns a body containing directory-index markers such as "
            "'Index of /'."
        ),
        evidence_requirements=["http_discovery_path"],
        remediation=(
            "Disable directory listing in the web server configuration, or add an index file to "
            "the directory. Review whether the directory contains files that should not have "
            "been published at all."
        ),
        check=check_directory_listing,
        requires=["http_discovery_path"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-011",
        title="Publicly retrievable configuration or repository file",
        category=RuleCategory.WEB,
        severity=Severity.CRITICAL,
        default_confidence=Confidence.HIGH,
        description=(
            "A file such as .env or .git/config is publicly retrievable with real content."
        ),
        detection=(
            "Fires when a GET to /.env, /.git/config and similar returns HTTP 200 and the body "
            "matches the signature for that file type."
        ),
        evidence_requirements=["http_discovery_path"],
        remediation=(
            "Remove the file from the web root immediately and rotate every credential it "
            "contained, since it must be assumed disclosed. Then fix the deployment so that the "
            "file cannot be served, and add a deployment check that requests these paths and "
            "fails the deploy if any returns 200."
        ),
        check=check_public_config_exposure,
        requires=["http_discovery_path"],
    ),
    RuleDefinition(
        rule_id="VEYL-WEB-012",
        title="Error response discloses internal detail",
        category=RuleCategory.WEB,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description="A 5xx response contains a stack trace or database error message.",
        detection=(
            "Fires when a response with status 500 or above has a body matching a known stack "
            "trace or database error signature."
        ),
        evidence_requirements=["http_response"],
        remediation=(
            "Configure the application to return a generic error page in production and log the "
            "detail server-side. Verify by triggering an error deliberately."
        ),
        check=check_http_error_disclosure,
        requires=["http_response"],
    ),
]
