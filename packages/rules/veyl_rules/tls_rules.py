"""TLS and certificate detection rules.

These rules read the ``tls_certificate`` and ``tls_configuration`` observations
produced by the TLS collector. Every value they reason about — expiry date,
negotiated protocol version, cipher suite, self-signed status — was recorded from
a completed handshake, so the finding can always be reproduced and re-checked.
"""

from __future__ import annotations

from datetime import UTC, datetime

from veyl_api.enums import Confidence, RuleCategory, Severity
from veyl_rules.framework import RuleContext, RuleDefinition, RuleMatch


def _parse(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def _days_remaining(not_after: object) -> int | None:
    parsed = _parse(not_after)
    if parsed is None:
        return None
    return (parsed - datetime.now(UTC)).days


def _cert_evidence(obs: dict, matcher: str) -> dict:
    return {
        "kind": "tls_certificate",
        "matcher": matcher,
        "detail": {
            "subject": obs.get("subject"),
            "issuer": obs.get("issuer"),
            "not_before": obs.get("not_before"),
            "not_after": obs.get("not_after"),
            "fingerprint_sha256": obs.get("fingerprint_sha256"),
            "san": (obs.get("san") or [])[:20],
            "is_self_signed": obs.get("is_self_signed"),
            "chain_valid": obs.get("chain_valid"),
            "hostname_valid": obs.get("hostname_valid"),
            "tls_version": obs.get("tls_version"),
            "cipher_suite": obs.get("cipher_suite"),
            "port": obs.get("port"),
        },
    }


def check_expired_certificate(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in context.of_kind("tls_certificate"):
        not_after = _parse(obs.get("not_after"))
        if not_after is None or not_after > datetime.now(UTC):
            continue
        days = _days_remaining(obs.get("not_after"))
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary=(
                    f"Certificate expired {abs(days) if days is not None else '?'} day(s) ago "
                    f"({not_after.date().isoformat()})"
                ),
                detection_explanation=(
                    f"A TLS handshake was completed on port {obs.get('port', 443)} and the "
                    f"presented certificate carries a notAfter of {not_after.isoformat()}, which "
                    f"is in the past. The subject is {obs.get('subject')!r} and the issuer is "
                    f"{obs.get('issuer')!r}."
                ),
                impact=(
                    "Clients that validate certificates will refuse the connection, which is an "
                    "availability problem first. The security problem is the response to it: "
                    "users and integrations under pressure to keep working are the population "
                    "that accepts certificate warnings or disables verification, and that "
                    "behaviour persists long after the certificate is renewed."
                ),
                evidence=[_cert_evidence(obs, f"not_after <= now (not_after={not_after.isoformat()})")],
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                risk_factors={"tls_issue": "expired", "days_past_expiry": abs(days) if days is not None else 0},
            )
        )
    return matches


def check_certificate_expiring_soon(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in context.of_kind("tls_certificate"):
        not_after = _parse(obs.get("not_after"))
        if not_after is None:
            continue
        days = (not_after - datetime.now(UTC)).days
        if days < 0 or days > 30:
            continue

        severity = Severity.HIGH if days <= 7 else Severity.MEDIUM
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary=f"Certificate expires in {days} day(s) on {not_after.date().isoformat()}",
                detection_explanation=(
                    f"The observed certificate on port {obs.get('port', 443)} has a notAfter of "
                    f"{not_after.isoformat()}, which is {days} day(s) away. Veyl reports this "
                    f"against a 30-day threshold; the value recorded here is the one the server "
                    f"presented during the handshake."
                ),
                impact=(
                    "An unattended expiry becomes an outage and, worse, trains users to click "
                    "through certificate errors. Renewal is usually straightforward; the risk is "
                    "that nothing tracks it."
                ),
                evidence=[
                    _cert_evidence(
                        obs, f"0 <= days_remaining <= 30 (days_remaining={days})"
                    )
                ],
                severity=severity,
                confidence=Confidence.HIGH,
                risk_factors={"tls_issue": "expiring_soon", "days_remaining": days},
            )
        )
    return matches


def check_self_signed_certificate(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in context.of_kind("tls_certificate"):
        if not obs.get("is_self_signed"):
            continue
        port = obs.get("port", 443)
        # On an internal host a self-signed certificate is often a deliberate,
        # acceptable choice. The hostname still tells us a lot, so we downgrade
        # rather than suppress, and say why.
        internal_hint = any(
            marker in context.asset_key.lower()
            for marker in ("internal", "dev", "test", "local", "staging")
        )
        severity = Severity.LOW if internal_hint else Severity.MEDIUM

        matches.append(
            RuleMatch(
                subject_suffix=f"port-{port}",
                summary=f"Self-signed certificate presented on port {port}",
                detection_explanation=(
                    f"During the TLS handshake on port {port}, the issuer and subject of the "
                    f"presented certificate were identical ({obs.get('issuer')!r}), which means "
                    f"the certificate is self-signed. Certificate chain validation returned "
                    f"{obs.get('chain_valid')}."
                    + (
                        " The asset name suggests an internal or non-production environment, so "
                        "Veyl has recorded this at LOW severity; a self-signed certificate on an "
                        "internal-only service can be a deliberate choice."
                        if internal_hint
                        else ""
                    )
                ),
                impact=(
                    "Self-signed certificates cannot be validated by a standard trust store. "
                    "Clients either reject the connection or are configured to ignore the error. "
                    "The second outcome is the dangerous one: once verification is disabled for "
                    "this host, an active attacker on the path can impersonate it, and the same "
                    "relaxed configuration tends to spread to other hosts."
                ),
                evidence=[
                    _cert_evidence(
                        obs, "tls_certificate.is_self_signed == true (subject == issuer)"
                    )
                ],
                severity=severity,
                confidence=Confidence.HIGH,
                risk_factors={"tls_issue": "self_signed", "internal_hint": internal_hint},
            )
        )
    return matches


def check_hostname_mismatch(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in context.of_kind("tls_certificate"):
        if obs.get("hostname_valid") is not False:
            continue
        port = obs.get("port", 443)
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{port}",
                summary=f"Certificate does not cover the hostname {context.asset_key}",
                detection_explanation=(
                    f"Veyl requested {context.asset_key} on port {port} and received a "
                    f"certificate whose Common Name is {obs.get('subject')!r} with SANs "
                    f"{(obs.get('san') or [])[:10]}. Neither the Common Name nor any SAN matches "
                    f"the requested hostname."
                ),
                impact=(
                    "A hostname mismatch means clients that validate certificates will reject the "
                    "connection or be reconfigured not to. Both weaken the guarantee that the "
                    "client is talking to the intended service."
                ),
                evidence=[
                    _cert_evidence(
                        obs,
                        f"hostname_valid == false for requested host {context.asset_key}",
                    )
                ],
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                risk_factors={"tls_issue": "hostname_mismatch"},
            )
        )
    return matches


def check_deprecated_tls_version(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in context.of_kind("tls_configuration"):
        if not obs.get("deprecated_version"):
            continue
        version = obs.get("tls_version")
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary=f"TLS {version} negotiated",
                detection_explanation=(
                    f"The handshake on port {obs.get('port', 443)} completed using {version}. "
                    f"The server offered this version and accepted it, so it is enabled rather "
                    f"than merely present on a deprecated list. The negotiated cipher suite was "
                    f"{obs.get('cipher_suite')!r}."
                ),
                impact=(
                    "TLS 1.0 and 1.1 are deprecated because their construction permits attacks "
                    "that later versions prevent, and because they cannot negotiate modern "
                    "authenticated ciphers. A client willing to use an old version can usually be "
                    "downgraded to it by an attacker on the path."
                ),
                evidence=[
                    {
                        "kind": "tls_configuration",
                        "matcher": f"tls_version == {version!r}",
                        "detail": {
                            "port": obs.get("port"),
                            "tls_version": version,
                            "cipher_suite": obs.get("cipher_suite"),
                            "deprecated_version": True,
                        },
                    }
                ],
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                risk_factors={"tls_issue": "deprecated_version", "tls_version": version},
            )
        )
    return matches


def check_weak_cipher(context: RuleContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for obs in context.of_kind("tls_configuration"):
        if not obs.get("weak_cipher"):
            continue
        suite = obs.get("cipher_suite")
        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary=f"Weak cipher suite negotiated: {suite}",
                detection_explanation=(
                    f"The handshake on port {obs.get('port', 443)} negotiated {suite}. This suite "
                    f"matches Veyl's weak-cipher signature list (RC4, 3DES, DES-CBC, NULL, EXPORT, "
                    f"MD5, anonymous key exchange)."
                ),
                impact=(
                    "The named constructions have known practical weaknesses: RC4 has "
                    "biases that leak plaintext under repetition, 3DES and DES have "
                    "insufficient effective key length for current compute budgets, MD5 "
                    "signatures are collision-prone, and anonymous suites provide no "
                    "authentication at all, which permits trivial interception."
                ),
                evidence=[
                    {
                        "kind": "tls_configuration",
                        "matcher": f"weak_cipher == true for cipher {suite!r}",
                        "detail": {
                            "port": obs.get("port"),
                            "tls_version": obs.get("tls_version"),
                            "cipher_suite": suite,
                            "weak_cipher": True,
                        },
                    }
                ],
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                risk_factors={"tls_issue": "weak_cipher", "cipher_suite": suite},
            )
        )
    return matches


def check_untrusted_chain(context: RuleContext) -> list[RuleMatch]:
    """Certificate chain failed validation for a reason other than the ones above."""
    matches: list[RuleMatch] = []
    for obs in context.of_kind("tls_certificate"):
        if obs.get("chain_valid") is not False:
            continue
        # Self-signed and expired already have their own, more specific rules.
        if obs.get("is_self_signed"):
            continue
        not_after = _parse(obs.get("not_after"))
        if not_after is not None and not_after <= datetime.now(UTC):
            continue

        matches.append(
            RuleMatch(
                subject_suffix=f"port-{obs.get('port', 443)}",
                summary="Certificate chain failed trust validation",
                detection_explanation=(
                    f"A verifying TLS handshake against port {obs.get('port', 443)} failed "
                    f"certificate validation. The certificate is not self-signed "
                    f"(issuer {obs.get('issuer')!r}, subject {obs.get('subject')!r}) and is not "
                    f"expired, so the failure is attributable to an incomplete chain, an unknown "
                    f"issuing authority, or a missing intermediate."
                ),
                impact=(
                    "Clients with a standard trust store cannot build a path to a trusted root and "
                    "will reject the connection. This is usually a deployment defect rather than "
                    "an attack, but it produces the same workaround behaviour as other trust "
                    "failures: verification gets disabled."
                ),
                evidence=[
                    _cert_evidence(obs, "chain_valid == false with is_self_signed == false")
                ],
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                risk_factors={"tls_issue": "incomplete_chain"},
            )
        )
    return matches


TLS_RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="VEYL-TLS-001",
        title="Expired TLS certificate",
        category=RuleCategory.TLS,
        severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        description="The TLS certificate presented by the service is past its notAfter date.",
        detection=(
            "Fires when a completed TLS handshake returns a certificate whose notAfter is in "
            "the past."
        ),
        evidence_requirements=["tls_certificate"],
        remediation=(
            "Renew and redeploy the certificate. Then check why the renewal did not happen: an "
            "expired certificate is normally a symptom of missing expiry monitoring rather than "
            "a one-off mistake. Add a check that alerts at 30, 14 and 7 days remaining."
        ),
        check=check_expired_certificate,
        requires=["tls_certificate"],
    ),
    RuleDefinition(
        rule_id="VEYL-TLS-002",
        title="TLS certificate expiring soon",
        category=RuleCategory.TLS,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description="The TLS certificate expires within 30 days.",
        detection=(
            "Fires when a completed TLS handshake returns a certificate with 0 to 30 days "
            "remaining. Severity is raised to HIGH at seven days or fewer."
        ),
        evidence_requirements=["tls_certificate"],
        remediation=(
            "Renew the certificate before expiry. Where possible move to automated issuance and "
            "renewal so this cannot recur."
        ),
        check=check_certificate_expiring_soon,
        requires=["tls_certificate"],
    ),
    RuleDefinition(
        rule_id="VEYL-TLS-003",
        title="Self-signed TLS certificate",
        category=RuleCategory.TLS,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description="The service presents a self-signed certificate.",
        detection=(
            "Fires when the issuer and subject of the presented certificate are identical. "
            "Downgraded to LOW when the asset name indicates an internal or non-production "
            "environment, where this is often deliberate."
        ),
        evidence_requirements=["tls_certificate"],
        remediation=(
            "Issue a certificate from a trusted authority. If the service is genuinely "
            "internal-only, a privately managed internal CA is the correct answer rather than a "
            "self-signed certificate, because it keeps verification enabled."
        ),
        check=check_self_signed_certificate,
        requires=["tls_certificate"],
    ),
    RuleDefinition(
        rule_id="VEYL-TLS-004",
        title="Certificate hostname mismatch",
        category=RuleCategory.TLS,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description="The certificate presented does not cover the requested hostname.",
        detection=(
            "Fires when neither the subject Common Name nor any subjectAltName entry matches the "
            "hostname Veyl requested."
        ),
        evidence_requirements=["tls_certificate"],
        remediation="Issue a certificate whose SANs include the hostname the service is reached by.",
        check=check_hostname_mismatch,
        requires=["tls_certificate"],
    ),
    RuleDefinition(
        rule_id="VEYL-TLS-005",
        title="Deprecated TLS protocol version negotiated",
        category=RuleCategory.TLS,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description="The server negotiated TLS 1.0 or 1.1.",
        detection=(
            "Fires when a completed handshake reports a protocol version in {TLSv1, TLSv1.1}. "
            "This proves the server accepts the version."
        ),
        evidence_requirements=["tls_configuration"],
        remediation=(
            "Disable TLS 1.0 and 1.1 on the listener and require TLS 1.2 or later. Inventory "
            "clients before doing so, since the reason these versions stay enabled is usually an "
            "unmaintained integration."
        ),
        check=check_deprecated_tls_version,
        requires=["tls_configuration"],
    ),
    RuleDefinition(
        rule_id="VEYL-TLS-006",
        title="Weak TLS cipher suite negotiated",
        category=RuleCategory.TLS,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description="The negotiated cipher suite uses a construction with known weaknesses.",
        detection=(
            "Fires when the negotiated cipher suite name matches a weak-construction signature: "
            "RC4, 3DES, DES-CBC, NULL, EXPORT, MD5 or anonymous key exchange."
        ),
        evidence_requirements=["tls_configuration"],
        remediation=(
            "Restrict the listener's cipher suite list to modern AEAD suites and remove the weak "
            "entries."
        ),
        check=check_weak_cipher,
        requires=["tls_configuration"],
    ),
    RuleDefinition(
        rule_id="VEYL-TLS-007",
        title="Certificate chain failed trust validation",
        category=RuleCategory.TLS,
        severity=Severity.LOW,
        default_confidence=Confidence.MEDIUM,
        description=(
            "A verifying handshake failed for a reason other than expiry or self-signing, "
            "typically a missing intermediate certificate."
        ),
        detection=(
            "Fires when certificate validation fails while the certificate is neither expired "
            "nor self-signed."
        ),
        evidence_requirements=["tls_certificate"],
        remediation=(
            "Serve the full certificate chain including any intermediate certificates, and "
            "verify against an independent client such as openssl s_client."
        ),
        check=check_untrusted_chain,
        requires=["tls_certificate"],
    ),
]
