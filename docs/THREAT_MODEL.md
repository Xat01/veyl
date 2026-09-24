# Threat Model

## Scope of this document

This covers threats to **Veyl itself** — the software, its data, and its deployment. It
does not cover the security of the assets Veyl assesses; findings about those are the
product's output, not its threat model.

The question this document answers is: *what can go wrong with a system that holds a map
of an organization's exposure and performs authorized network activity, and what has been
done about each case?*

## Assets worth protecting

Ordered by consequence if lost.

| Asset | Why it matters |
| --- | --- |
| **The exposure map** | A consolidated inventory of what an organization runs, where it is weak, and what is business-critical. This is reconnaissance already done. |
| **Scope authorizations** | Records of who permitted what to be tested. Their integrity is the legal basis for the scanning. |
| **The audit log** | Who did what, when. Needed for accountability and incident reconstruction. |
| **TOTP secrets** | Stored encrypted, not hashed, because verifying a code requires the plaintext. Whoever holds `VEYL_SECRET_KEY` holds these. |
| **Session tokens** | Bearer credentials for the API. |
| **Credentials** | Passwords (bcrypt), recovery codes (bcrypt), WebAuthn public keys (not secret). |
| **Observed data** | Response headers, certificates, banners, and page content captured from customer systems. May itself contain secrets. |

## Adversaries

**A1 — Unauthenticated internet attacker.** Reaches a Veyl instance that has been exposed.
Wants the exposure map, or wants to use Veyl as a scanning proxy to attack third parties.

**A2 — Malicious or compromised tenant user.** Has valid credentials in one organization.
Wants another organization's data.

**A3 — A user who is over-privileged or whose account was taken over.** Wants to expand
access, persist, or cover tracks.

**A4 — Someone who has obtained database access.** Wants to alter history — delete an
authorization record, change a finding, remove an audit entry.

**A5 — A victim of scanning.** A third party who notices Veyl probing their systems. The
relevant harm is not to Veyl; it is that Veyl caused unauthorized traffic, and that the
evidence trail must show why the traffic was legitimate.

**A6 — Veyl's own operators.** Not assumed hostile, but assumed capable of mistakes. The
system should make the dangerous thing hard, not merely discouraged.

## Threats and mitigations

### T1 — Veyl used as an SSRF proxy

*The highest-severity threat in this document.* If an attacker can make Veyl fetch a URL
of their choosing, Veyl becomes a privileged position inside the customer's network: it
sits next to internal services and, in cloud deployments, next to the instance metadata
service that hands out credentials.

**Mitigation.** `veyl_api/safety/firewall.py`. Resolve first, then validate **every**
returned address. Reject loopback, link-local, private, reserved, multicast, unspecified,
and metadata endpoints. Validation runs on the resolved binary address, not the string,
which is what holds against the encoding tricks that defeat string matching:

| Encoding | Example | Why string checks miss it |
| --- | --- | --- |
| decimal | `2130706433` | a valid integer form of `127.0.0.1` |
| hex | `0x7f000001` | same address, different notation |
| short form | `127.1` | expands to `127.0.0.1` |
| IPv4-mapped IPv6 | `::ffff:127.0.0.1` | not a loopback *string*, is a loopback *address* |
| NAT64 | `64:ff9b::/96` | embeds an IPv4 address inside IPv6 |
| 6to4 | `2002::/16` | embeds an IPv4 address inside IPv6 |

**DNS rebinding is addressed.** The classic gap in resolve-then-validate is that the name
resolves to a public address at validation time and a private one at connection time. Veyl
does not connect by name: every collector dials the specific validated address.

- TCP connect scanner dials the vetted IP, never the hostname.
- TLS collector dials the validated address and passes the hostname only as the SNI /
  certificate-validation name.
- HTTP collector pins the connection the same way, and applies the check again on every
  redirect hop rather than only on the initial URL.

**Residual risk.** `VEYL_ALLOW_PRIVATE_TARGETS=true` disables the private-range check. It
exists for the bundled demo. It is recorded on the organization when set, but it is a
switch that can be left on by accident. Do not enable it in production.

**Residual risk.** Only the first validated address is dialled for a given host. A host
whose *other* addresses are sensitive is not probed, which is the safe direction, but it
means a multi-homed host is assessed at one address rather than all of them.

### T2 — Unauthorized scanning of third parties

Veyl probing systems nobody authorized is both a legal exposure for the customer and a
reputational one for this project.

**Mitigation.** The Scope Registry. Entries are `PENDING` on creation and scannable only
after an explicit, audited authorization. Authorization is re-resolved at scan submission
so a lapsed attestation cannot be exploited by submitting a scan request. Domain matching
is on label boundaries, so authorizing `example.com` does not authorize
`example.com.attacker.net`. Port overrides require per-entry opt-in.

**Residual risk.** Someone with authorization rights can authorize a target they have no
right to authorize. Veyl cannot verify that a customer owns what they claim. The product
records who asserted it and when, which is the correct division of responsibility: the
system makes authorization explicit and attributable rather than attempting to be the
authority itself.

### T3 — Cross-tenant data access

**Mitigation.** Every tenant-scoped table carries `organization_id` via the `OrgScoped`
mixin. The organization is resolved from the authenticated context, with explicit
precedence: an `X-Organization` header (slug or id), then a token claim, then the single
membership if there is exactly one. A token naming an organization the user is not a member
of is a `403`, not a silent fallback.

**Residual risk.** Enforcement is application-level. There is no database row-level
security, so a single missing filter is a cross-tenant read. This is tested for, but it is
a property maintained by discipline rather than by the database engine.

### T4 — Audit log tampering

**Mitigation.** Per-tenant hash chain. Each entry stores `prev_hash` and `entry_hash`;
`verify_chain()` detects modification or removal of a historical row.

**Residual risk.** The chain makes tampering *evident*, not *impossible*. An attacker with
database write access can rewrite the entire chain from the point of alteration forward,
and nothing outside the database would contradict them. A real control requires an
append-only store or an external anchor (a signature, a periodic hash published
elsewhere). Not implemented.

### T5 — Fabricated findings

A security tool that invents findings is worse than one that finds nothing: it destroys the
operator's ability to trust any of the output, and it wastes the time of the people who
respond.

**Mitigation.** The evidence contract. A rule match must cite at least one observation it
actually read, and must supply a matcher description, an explanation, and an impact
statement. Matches that cannot are rejected. Rules are pure functions with no I/O, so a rule
cannot manufacture the observation it cites.

**Mitigation.** Provenance. Every observation is tagged `OBSERVED`, `INFERRED`, or
`USER_PROVIDED`, and confidence is `LOW`/`MEDIUM`/`HIGH`. A version read from a banner and
a version inferred from behaviour are not presented as equivalent.

**Mitigation.** No fabricated versions or CVEs. Version strings are reported only when
fingerprinted; unknown is a valid answer. CVEs are mapped only on version-range evidence,
never on product-name similarity.

**Mitigation.** AI is off by default (`ai_enabled=False`). Where interpretation is layered
on, it cites the same evidence a human would read and does not introduce new claims.

### T6 — Credential attacks against the API

**Mitigation.** bcrypt password hashing; strength validation at set time; progressive
lockout on repeated failures within a window; per-account failure counters; rate limiting;
short-lived access tokens. Every authentication outcome — success, failure, lockout, MFA
event — is audited.

**Residual risk.** Lockout is a denial-of-service vector against a known account. The
threshold and window are tuned to be a speed bump rather than a hard stop, which is a
deliberate trade.

### T7 — Privileged account takeover

An `ADMIN` can authorize scanning of arbitrary assets and read the whole exposure map.

**Mitigation.** A second factor is mandatory for privileged accounts, enforced at login
(no token issued), at refresh (no session renewed), and at role grant (the role cannot be
given to an account without a factor). An account cannot remove its own last factor while
privileged.

**Note on why three enforcement points.** During development, a test caught a real bug
here: the guard that was supposed to prevent removing the last factor short-circuited when
the account *already had* a factor, so it never fired and an `ADMIN` could strip their own
second factor. Enforcing a policy at one point in a system with several entry points is how
that happens.

**Residual risk.** TOTP secrets are encrypted under a key derived from `VEYL_SECRET_KEY`.
An attacker who obtains both the database and the secret key obtains the TOTP seeds. This
is inherent to TOTP: it cannot be hashed, because verifying a code requires the seed.

### T8 — WebAuthn weakness

**Mitigation.** Single-use, expiring challenges; challenge consumed even on failure;
origin checked against the configured CORS list by exact match; RP ID checked by hashing
the host; signature verified over `authData || sha256(clientDataJSON)`; sign-count
regression detected.

**Residual risk — significant.** **Attestation is parsed but not evaluated.** No trust
anchor chain is checked, so a self-made software authenticator is accepted. Registration
therefore proves possession of a private key and nothing about where it lives. A hardware
key is not enforced, only supported.

### T9 — Command injection

**Mitigation.** Scans are performed over sockets by the Python process. When an external
tool is invoked, arguments are passed as a list with `shell=False` and user-influenced
values are validated against a strict pattern first. There is no path where an asset name
is concatenated into a command string.

**Residual risk.** The optional Nmap backend (`nmap_enabled=False` by default) shells out
to a binary. The argument construction is list-based and validated, but enabling it adds an
external dependency to the trusted computing base.

### T10 — Hostile data from scanned systems

Scanned systems are untrusted. A banner, header, or certificate field can contain anything,
including content designed to exploit whatever parses it.

**Mitigation.** Observation payloads are sanitized before storage and treated as hostile
everywhere downstream. Nothing is rendered unescaped, interpolated into SQL, or passed to a
shell. Report generation escapes values. Payload size is truncated. The report template
renders through Jinja2 with autoescaping.

**Residual risk.** Parsers for TLS certificates and HTTP headers are a real attack surface
and are not fuzzed.

### T11 — Secrets in observed data

Response bodies and headers captured from customer systems may contain API keys, tokens, or
session identifiers. Veyl is then storing secrets it was never meant to hold.

**Mitigation.** Collection is bounded to security-relevant headers and metadata rather than
full response bodies wherever possible; stored payloads are truncated.

**Residual risk.** Partial. Where content is captured, it is captured. The database
containing the exposure map should be treated as sensitive at rest, and encryption at rest
is a deployment responsibility.

## Threats explicitly out of scope

- **Physical access** to the host or its storage.
- **A compromised supply chain** — a malicious dependency, a poisoned build.
- **A malicious operator with full infrastructure access.** Such a party can read the
  database and the secret key. Veyl reduces their ability to act undetectably; it does not
  prevent them from acting.
- **Denial of service.** The API has rate limiting, but no defence against a determined
  volumetric attack. Put it behind infrastructure that does.
- **Security of the assets assessed.** That is the product's output.

## Assumptions

1. **TLS terminates in front of the API** in any non-local deployment. The API speaks plain
   HTTP.
2. **`VEYL_SECRET_KEY` is strong and secret.** It signs sessions and encrypts TOTP seeds.
   The shipped default is a development placeholder that is only safe because the default
   bind is loopback.
3. **The database is not internet-reachable.**
4. **`VEYL_ENV=production` in production.** It tightens defaults.
5. **The customer has the right to authorize the targets they register.** Veyl records the
   assertion; it does not verify ownership.
6. **Operators read the deployment section of [SECURITY.md](../SECURITY.md).** Several
   protections are opt-out rather than impossible to disable.

## Review

This model should be revisited when: a new collector or scanning backend is added, a new
authentication method is introduced, the deployment topology changes, or the AI
interpretation layer is enabled. It has not been reviewed by an external party.
