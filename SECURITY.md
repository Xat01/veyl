# Security Policy

Veyl is a security tool. It holds the map of what an organization exposes, which makes
it a high-value target itself, and it performs network activity that is only lawful when
authorized. Both facts shape this document.

## Reporting a vulnerability

Report privately. Do not open a public issue for a vulnerability.

- Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository (Security → Report a vulnerability).
- If that is unavailable, contact the maintainers directly.

Please include: affected version or commit, a description of the impact, reproduction
steps or a proof of concept, and any suggested remediation. If you need to send
something sensitive, say so in your first message and we will arrange a channel.

**What to expect.** We aim to acknowledge within 3 business days, and to give an initial
assessment within 10. We will tell you what we found, whether we consider it in scope,
and what we intend to do — including when the answer is "we are not going to fix this,
and here is why." We will credit you in the advisory unless you ask us not to.

**Please do not** test against systems you do not own, run denial-of-service or load
tests against shared infrastructure, or access data belonging to others. If you would
otherwise have to do one of those things to demonstrate an issue, contact us first.

## Supported versions

Pre-1.0. Only the `main` branch is supported. There are no backports; fixes land on
`main`.

## Security model

### Authorization before capability

The Scope Registry is the boundary between "this software can reach a host" and "this
software is permitted to assess a host." The distinction is enforced, not documented:

- A newly created scope entry is `PENDING` and is not scannable. Somebody must
  explicitly change it to `AUTHORIZED`, and that change is written to the audit log with
  who made it.
- Authorization is re-evaluated **at scan submission**, not only at entry creation. An
  entry that expired, was revoked, or was deactivated in between is refused by name with
  the specific reason, and the refusal is recorded on the scan.
- Domain matching is on label boundaries, so authorizing `example.com` does not silently
  authorize `notexample.com` or `example.com.attacker.net`.
- Port overrides are honored only for entries that explicitly opted in. Neither silently
  ignoring nor silently honoring the request is acceptable.

### SSRF floor

Anything that performs a lookup on a user-influenced name resolves the name first and
then validates **every** returned address, because a hostname can resolve to a mix of
public and private addresses and checking one is not checking the set. Rejected:
loopback, link-local, private ranges, reserved space, multicast, unspecified, and cloud
metadata endpoints.

The checks operate on the resolved binary address, not on the string, which is what makes
them hold against the encodings that defeat naive filters: decimal (`2130706433`), hex,
short forms (`127.1`), IPv4-mapped IPv6 (`::ffff:127.0.0.1`), NAT64 (`64:ff9b::/96`), and
6to4 (`2002::/16`).

`VEYL_ALLOW_PRIVATE_TARGETS` lifts the floor for private ranges. It exists so the bundled
demo can scan a service on loopback. It is recorded on the organization when enabled, so
a demo instance cannot be mistaken for a hardened deployment. Do not enable it in
production.

### Never build a shell command from user input

Scans are performed over sockets by the Python process. When an external tool is invoked,
arguments are passed as a list to `subprocess` with `shell=False`, and user-influenced
values are validated against a strict pattern before they become arguments. There is no
code path where an asset name is concatenated into a command string.

### Evidence integrity

A finding is not free-form text. It must reference the observation it was derived from.
The evidence contract rejects a rule match that cites no evidence, references an
observation kind that was never collected, or omits its explanation, impact, or
remediation.

**A language model never creates evidence.** Findings, risk factors, and CVEs are
produced by deterministic code against observed data. If interpretation is ever layered
on top, it cites the same evidence a human would read; it does not introduce new claims.

### Authentication and privileged accounts

- Passwords are hashed with bcrypt. Strength is validated at set time.
- Login is rate-limited with progressive account lockout: repeated failures within a
  window lock the account for a period, and each failure is audited.
- **Accounts holding a privileged role (currently `ADMIN`) must have a second factor.**
  This is a policy, enforced at three points: login refuses to issue a token to a
  privileged account without one, refresh refuses to renew such a session, and the role
  cannot be *granted* to an account that has no factor. The last two exist because the
  first alone is trivially bypassed by minting or extending a session.
- TOTP secrets are stored encrypted (Fernet, key derived from `VEYL_SECRET_KEY`), not
  hashed, because verifying a code requires the plaintext. **This means `VEYL_SECRET_KEY`
  protects those secrets** — treat it as key material and rotate it if it leaks, knowing
  that rotation requires re-enrolling TOTP.
- Recovery codes are hashed and single-use.
- An account cannot remove its own last factor while it remains privileged. Removing a
  factor that would leave a privileged account with none is refused.
- WebAuthn supports ES256/ES384/ES512 and RS256 with single-use, expiring challenges and
  sign-count regression detection. **Attestation is parsed but not evaluated** — no trust
  anchor is checked, so registration proves possession of a key, not that the key came
  from certified hardware.
- Session tokens are short-lived JWTs. `SESSION_REVOKED` is audited.

### Tamper-evident audit log

Audit entries are chained per tenant: each entry stores the hash of the previous entry
and its own hash over its content. Altering or removing a historical row breaks the
chain, and `verify_chain()` detects it. This makes tampering evident; it does not make it
impossible for someone with direct write access to the database — an append-only,
externally-anchored log is the stronger control and is not implemented here.

### Tenant isolation

Every tenant-scoped table carries `organization_id` through a shared mixin, and queries
are filtered by the organization resolved from the authenticated context. Cross-tenant
reads are a bug class we test for, but the enforcement is application-level rather than
database-level row security. Do not rely on this alone for hostile multi-tenancy.

### Known limitations

Stated plainly so nobody has to discover them:

- **Attestation is not verified** (see above).
- **The audit log is application-level**, not append-only at the storage layer.
- **Scans run synchronously** in the API process. Long scans hold a request open. There
  is no worker, and no queue. This is a capacity limitation, not a safety one.
- **No database-level row security.** Tenant isolation is application-enforced.
- **PDF reporting returns 501.** Deliberately not implemented rather than half-implemented.
- **The `apps/web` console does not exist yet.** Its absence is not a security control.
- **The demo environment sets a known password and enables private targets.** It is for
  local evaluation only and says so when it runs.

## Deployment guidance

- **Set `VEYL_SECRET_KEY` to a strong random value.** It signs session tokens and
  encrypts TOTP secrets. The default is a development placeholder and is safe only
  because it is only reachable locally.
- **Keep the API off the public internet.** It is bound to loopback by default. Put it
  behind an authenticating proxy if it must be reachable, and terminate TLS there.
- **Run `VEYL_ENV=production`.** It tightens defaults; do not run production with a
  development environment name.
- **Leave `VEYL_ALLOW_PRIVATE_TARGETS` off.** Enabling it in production defeats the SSRF
  floor.
- **Set `VEYL_CORS_ORIGINS` to your real console origin.** WebAuthn origin checks are
  derived from it; a wildcard weakens them.
- **Back up the database.** Losing it loses the audit chain, and the chain cannot be
  reconstructed.
- **Register only assets you own or are authorized in writing to test.** Veyl makes this
  easier to do correctly. It does not make unauthorized testing lawful.
