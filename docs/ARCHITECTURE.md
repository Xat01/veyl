# Architecture

## The one-sentence version

Veyl turns facts observed on authorized assets into evidence-backed findings, correlates
those facts across time into exposure changes and potential attack paths, and prioritizes
the result using business context the customer supplied.

## Why the pipeline is shaped this way

Most exposure tools collapse collection, judgment, and presentation into one step: a
scanner returns a list of problems and the UI renders it. That shape has three failure
modes that this architecture exists to prevent.

1. **Findings with no provenance.** If the thing that decides "this is a problem" is also
   the thing that gathers the data, there is no moment where anyone can ask *what did you
   actually see?* Evidence becomes a prose description rather than a record.
2. **Judgment that cannot be re-run.** If analysis happens during collection, changing a
   rule means re-scanning the internet. Analysis should be replayable against stored
   observations.
3. **Confidence that is not tracked.** A version read from a banner and a version inferred
   from behaviour are not equally trustworthy. If nothing distinguishes them, the weakest
   evidence sets the tone for the strongest.

So the pipeline is deliberately four stages with hard boundaries between them, and each
boundary is a place where data can be inspected, tested, or replayed.

```
   Scope Registry          (authorization)
          |
          v
   Safety floor            (SSRF, port validation)
          |
          v
   Collectors              (DNS, TCP, TLS, HTTP)
          |
          v  ObservationPayload
   Observations            (immutable, provenance-tagged)
          |
          v  RuleContext
   Rules                   (pure functions, no I/O)
          |
          v  RuleMatch + Evidence
   Findings                (evidence contract enforced)
          |
          +--> Risk model       (transparent additive factors)
          +--> Change detection (snapshot diffs)
          +--> Graph + paths    (correlation)
          +--> Reporting        (HTML, JSON)
```

## Stage boundaries, and what each one guarantees

### 1. Scope Registry — authorization

The registry is the boundary between *capable* and *permitted*. A scope entry is created
`PENDING` and is not scannable. Somebody must explicitly authorize it, and that change is
audited with who made it and when.

Authorization is re-resolved at **scan submission**, not just at entry creation. An entry
that expired, was revoked, or was deactivated in between is refused by name with a reason,
and the refusal is recorded on the scan. This matters because the gap between "we
registered this" and "we scanned this" can be months.

Domain matching is on label boundaries. Authorizing `example.com` does not authorize
`notexample.com` or `example.com.attacker.net` — both of which a naive suffix check would
wave through.

### 2. Safety floor — SSRF defence

`veyl_api/safety/firewall.py`. Every candidate target is resolved and **every** returned
address is validated. A hostname can resolve to a mix of public and private addresses;
validating one is not validating the set.

Rejected: loopback, link-local, private, reserved, multicast, unspecified, and cloud
metadata endpoints. The checks run against the resolved binary address rather than the
string, which is what makes them hold against decimal (`2130706433`), hex, short forms
(`127.1`), IPv4-mapped IPv6 (`::ffff:127.0.0.1`), NAT64 (`64:ff9b::/96`), and 6to4
(`2002::/16`).

`VEYL_ALLOW_PRIVATE_TARGETS` lifts the private-range restriction so the bundled demo can
scan loopback. It is recorded on the organization when enabled.

### 3. Collectors — observation

`services/scanner/`. Collectors implement a `Protocol`, not an ABC, so an alternative
backend (an Nmap adapter, an external feed, a lab fixture) only has to *look* right and
nothing downstream learns which one is in use.

Collectors emit `ObservationPayload` and nothing else. They do not decide anything, do not
write findings, and never see an unauthorized target. A failure in one target or one
collector never aborts the scan — it is recorded and the scan continues.

`data` is treated as hostile everywhere downstream: sanitized before storage, never
interpolated into SQL, never rendered unescaped, never passed to a shell.

### 4. Observations — the immutable record

An observation is one fact about one subject, with:

- `kind` — what sort of fact (`http_security_headers`, `tls_certificate`, `port_state`…)
- `subject` — what it is about
- `data` — the verbatim payload
- `provenance` — `OBSERVED`, `INFERRED`, or `USER_PROVIDED`
- `confidence` — `LOW`, `MEDIUM`, `HIGH`
- `observed_at` — when

Observations are never mutated. A re-scan writes new ones. This is what makes the evidence
chain auditable after the fact: a finding from three months ago still points at the bytes
that produced it.

### 5. Rules — judgment

`packages/rules/`. A rule is a pure function from a `RuleContext` to `RuleMatch` objects.
It has no network access, no database access beyond what the evaluator hands it, and no
ability to invent evidence.

`RuleContext` is deliberately narrow: observations for a single asset from a single scan,
plus a small amount of derived context. It cannot query the database, make network calls,
or see other tenants. This is what makes rules trivially testable and replayable — you can
run the whole rule set against a fixture with no infrastructure.

**The evidence contract.** A rule match must cite at least one observation it actually
read, and must supply a matcher description, an explanation, and an impact statement. A
match that cannot is rejected rather than stored. This is the constraint the product's
central claim rests on: *if a rule cannot point at an observation, it cannot raise a
finding.*

37 rules ship across 8 categories. See [DETECTION_RULES.md](DETECTION_RULES.md).

### 6. Findings — the unit of work

A finding ties together the rule, the evidence, the risk assessment, the business context,
and the remediation state. It has a lifecycle (`OPEN` → acknowledged → resolved, etc.) and
an append-only event history, so the question "when did this change and who changed it"
has an answer.

## Cross-cutting subsystems

### Risk model — transparent by construction

`services/analyzer/veyl_analyzer/risk.py`. Additive and capped at 100. Every finding
carries a `factors` dictionary naming each contribution and its weight, and the UI renders
that dictionary rather than the number alone.

| Factor | Max |
| --- | --- |
| base severity | 40 |
| internet exposure | 15 |
| business criticality | 15 |
| data classification | 10 |
| confidence | 8 |
| vulnerability evidence | 7 |
| environment | 3 |
| service class | 2 |

Base severity tops out at 40 on purpose: severity can never dominate the list alone. An
INFO finding on a critical, internet-exposed, sensitive-data production asset outranks a
HIGH finding on an unclassified internal host, and that is the correct ordering for this
product.

There is no machine learning and no opaque weighting. An unexplainable priority score is
worse than no score: it cannot be argued with, cannot be tuned, and implies a precision
that is not there.

### Change detection — snapshots, not diffs of findings

`AssetSnapshot` stores a canonical `state` document and its `state_hash`. A re-scan
produces a new snapshot; comparing consecutive snapshots yields `ExposureChange` records
classified as risk-increasing, risk-reducing, or neutral.

Diffing *state* rather than *findings* matters. A finding that disappears because a rule
was tuned is not a remediation, and a finding that appears because a rule was added is not
a new exposure. Snapshot diffing reports what changed about the asset.

### Correlation — graph and attack paths

`services/correlation/`. The attack-surface graph is materialized with stable `node_key`
values (`type:identifier`) so rebuilds are idempotent — the same input produces the same
graph, and rebuilding does not duplicate.

Attack paths are correlated from graph adjacency plus observed exposure. **The language is
deliberate: "potential attack path", never "confirmed attack".** A path is a hypothesis
about reachability derived from structure. It has not been exploited, and the product does
not claim it has. `GraphNode` carries a `risk_score`; `GraphEdge` carries only a structural
`weight`, because an edge does not have a risk of its own.

### Audit log — tamper-evident

`veyl_api/audit.py`. Entries are chained per tenant: each stores the hash of the previous
entry and a hash over its own content. `verify_chain()` detects alteration or removal of a
historical row. This makes tampering *evident*; it does not make it impossible for someone
with direct database write access. An append-only, externally anchored log is the stronger
control and is not implemented.

### Authentication

`veyl_api/security/`. JWT sessions, bcrypt passwords, progressive lockout, TOTP, and
WebAuthn (ES256/ES384/ES512/RS256) with single-use expiring challenges and sign-count
regression detection.

The privileged-account policy — **an `ADMIN` must have a second factor** — is enforced at
three points: login refuses to issue a token, refresh refuses to renew a session, and the
role cannot be *granted* to an account without a factor. The first two exist because
enforcing only at login is bypassed by extending a session that already exists.

TOTP secrets are encrypted (Fernet, key derived from `VEYL_SECRET_KEY`) rather than hashed,
because verifying a code requires the plaintext. Recovery codes are hashed and single-use.

WebAuthn attestation is parsed but **not evaluated** — no trust anchor chain is checked.
Registration proves possession of a key, not that the key is certified hardware.

## Data model

25 tables. The ones that carry the architecture:

| Table | Role |
| --- | --- |
| `organizations`, `organization_members`, `users` | tenancy and identity |
| `scope_entries` | the authorization boundary |
| `scans` | one assessment run, with per-target outcomes |
| `assets`, `services`, `certificates` | normalized current state |
| `observations` | the immutable evidence base |
| `rule_definitions` | rule catalogue persisted for reproducibility |
| `findings`, `evidence`, `finding_events` | the work product and its history |
| `asset_snapshots`, `exposure_changes` | change over time |
| `graph_nodes`, `graph_edges`, `attack_paths` | correlation |
| `remediations` | ownership and closure |
| `reports` | generated artifacts |
| `audit_logs` | the hash chain |
| `webauthn_credentials`, `auth_challenges` | hardware-key auth |

Every tenant-scoped table carries `organization_id` through a shared `OrgScoped` mixin.
Enforcement is application-level; there is no database row-level security.

## Deployment shape

Monorepo, one Python distribution. `pyproject.toml` maps each importable package to its
source directory explicitly rather than relying on discovery, so the published top-level
module names are obvious from that file alone.

- `apps/api` — FastAPI, SQLite by default, Postgres optional
- `packages/rules`, `services/*` — libraries, no process of their own
- `apps/web` — Next.js console, **scaffold only, not built**

There is no worker process. Scans run synchronously inside the API request. See
[DEPLOYMENT.md](DEPLOYMENT.md) for the capacity implication and what a real queue would
need to look like.

## Deliberate non-goals

- **Active exploitation, brute forcing, credential testing.** Permanently out of scope.
- **An opaque risk score.** The model shows its work or it does not ship.
- **A finding without evidence.** Rejected by contract, not by convention.
- **Guessing.** An unknown version is reported as unknown. A CVE is mapped only on
  version-range evidence, never on a product name that looks similar.
