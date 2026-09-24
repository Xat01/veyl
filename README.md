# Veyl

**Continuous Exposure Intelligence** — Know what your business exposes. Understand why it matters. Fix what actually puts you at risk.

Veyl is not a scanner wrapper. Scanning is one input. The product is the chain that
turns what was *observed* on an authorized asset into evidence-backed findings,
correlates those across time into exposure changes and potential attack paths, and
tells a business which of its systems to fix first and why.

Three properties are load-bearing and enforced in code, not in documentation:

- **It only scans what you have authorized.** Every scan resolves authorization at
  submit time against the Scope Registry. An entry that expired, was revoked, or was
  deactivated is refused, by name, with a reason.
- **Every finding cites evidence.** A finding cannot exist without an observation to
  point at, a detection rule, an explanation, and an impact statement. The evidence
  contract rejects a match that cannot supply them.
- **Unknown is an allowed answer.** Service versions are reported only when
  fingerprinted; CVEs are mapped only on version-range evidence, never on a product
  name that looks similar. "We don't know" beats a confident wrong answer.

## Status: what is real, and what is not

This is an alpha. Being precise about the boundary is part of the product's claim,
so the boundary is stated here rather than discovered later.

**Implemented and tested**

| Area | State |
| --- | --- |
| Scope Registry + authorization model | Implemented. Pending-by-default; explicit authorization required and audited. |
| Discovery: DNS, subdomains, CT logs, TCP connect scan, TLS, HTTP, fingerprinting | Implemented. |
| Deterministic rule engine + evidence contract | Implemented. 8 rule modules. |
| Transparent additive risk model | Implemented. Shows its factors; no opaque score. |
| Snapshot-based change detection | Implemented. |
| Attack-surface graph + potential attack paths | Implemented. |
| Business context (criticality, data class, owner) | Implemented, provenance-tracked. |
| Remediation tracking | Implemented. |
| Reports: HTML and JSON | Implemented. |
| REST API + JWT auth, MFA (TOTP), WebAuthn, lockout, RBAC | Implemented. |
| Tamper-evident audit log (per-tenant hash chain) | Implemented, with `verify_chain()`. |
| AcmePay demo environment | Implemented. One command, real scans. |

**NOT IMPLEMENTED — do not expect these**

- **PDF reports.** The endpoint returns `501 Not Implemented` on purpose. A format
  request that returns a broken file is worse than one that says no.
- **The Next.js console (`apps/web`).** Scaffolded, not built. There is currently no
  web UI; the API and the generated HTML reports are the interface.
- **Background job queue.** Scans run synchronously inside the API request. There is no
  worker process, and no `veyl-worker` command ships. Submitting to a queue with nothing
  consuming it would present as a hang, which is a worse failure than a slow request.
- **Scheduled / recurring scans.** Scans are triggered by a user or the demo.
- **Active exploitation, brute forcing, credential testing.** Out of scope permanently,
  not merely unbuilt.
- **Attestation verification for WebAuthn.** Attestation statements are parsed but not
  evaluated; no trust anchor chain is checked. Registration proves key possession only.
- **Cloud provider inventory, agent-based collection, third-party integrations.**
- **Shared schemas package (`packages/schemas`).** Referenced by an earlier draft of this
  file; it does not exist. Contracts live in `apps/api/veyl_api/api/schemas.py`.

## Repository layout

```
apps/api              FastAPI application: HTTP layer, models, safety floor, auth
apps/web              Next.js console — SCAFFOLD ONLY, not built (see Status)
packages/rules        Deterministic detection rules + rule framework
services/scanner      Authorized discovery: DNS, ports, TLS, HTTP, fingerprinting
services/analyzer     Rule evaluation -> findings + evidence + risk
services/correlation  Change detection, attack-surface graph, attack paths
services/reporting    HTML and JSON report generation
demo/targets          The bundled AcmePay service the demo scans
demo/scripts          The Day 1 -> Day 7 scenario walkthrough
tests                 Unit, integration, and security suites
```

## Quick start

Requires Python 3.11+ (developed on 3.13).

```bash
python -m venv .venv
. .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Build the demo environment, then start the API:

```bash
python -m veyl_api.demo        # seeds AcmePay and runs the Day 1 -> Day 7 scans
python -m veyl_api             # API on http://127.0.0.1:8000
```

`veyl-api` and `veyl-demo` are installed as console scripts by `pip install -e`, and are
equivalent to the `python -m` forms above. The demo prints the login credentials and the
TOTP secret for the admin account at the end of its run — read them from there.

Interactive API documentation is served at `http://127.0.0.1:8000/docs`.

Useful flags:

```bash
python -m veyl_api.demo --reset        # drop and recreate the demo database first
python -m veyl_api.demo --skip-scans   # seed accounts and scope only
python -m veyl_api --port 9000         # bind elsewhere
python -m veyl_api --host 0.0.0.0      # reachable from the network — opt in deliberately
```

The API binds to loopback by default. `--reload` is refused in combination with a
non-loopback bind or a production environment.

## Tests

```bash
python -m pytest               # full suite
python -m pytest tests/security -v    # the safety properties specifically
ruff check .
```

The security suite covers the properties the product depends on: the SSRF floor
(loopback, link-local, cloud metadata, numeric and IPv4-mapped encodings), scope
enforcement boundaries, audit-chain tamper detection, the evidence contract, and the
privileged-account authentication policy.

## Configuration

Copy `.env.example` to `.env` and edit. The settings that matter most:

| Setting | Purpose |
| --- | --- |
| `VEYL_SECRET_KEY` | Signs JWTs and derives the key that encrypts TOTP secrets. **Change it.** |
| `VEYL_DATABASE_URL` | Defaults to SQLite. Postgres via `pip install -e ".[postgres]"`. |
| `VEYL_ALLOW_PRIVATE_TARGETS` | Must be `true` to scan RFC1918/loopback targets. Set by the demo; leave off elsewhere. |
| `VEYL_ENV` | `development` / `staging` / `production`. Tightens defaults as it rises. |
| `VEYL_CORS_ORIGINS` | Allowed browser origins. WebAuthn validates against these. |

## Security

See [SECURITY.md](SECURITY.md) for the disclosure process and the security model.

Veyl scans only assets explicitly registered in the Scope Registry with a valid,
unexpired authorization record, re-checked at scan time. If you point it at a system you
do not own or have written permission to test, you are misusing it.

## License

Apache-2.0. See [LICENSE](LICENSE).
