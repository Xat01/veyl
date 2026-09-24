# API Reference

Base path `/api`. Interactive documentation at `/docs` (OpenAPI), and the raw schema at
`/openapi.json`. **48 paths.**

The running app is the authoritative reference; this document explains the conventions and
the parts of the design that the schema cannot express.

## Authentication

`Authorization: Bearer <access_token>`, obtained from `POST /api/auth/login`.

Access tokens are JWTs valid for `access_token_ttl_minutes` (default 60). Refresh tokens
last `refresh_token_ttl_days` (default 7) and are exchanged at `POST /api/auth/refresh`.

### Choosing an organization

The tenant is resolved per request, in this order:

1. `X-Organization: <slug-or-id>` header
2. the `org` / `org_id` claim in the token
3. the caller's single membership, if they have exactly one

If none applies, the request is a `400`. A token naming an organization the user is not a
member of is a `403` — never a silent fallback to another tenant.

### Login and the second factor

`POST /api/auth/login` takes `email`, `password`, and optionally `totp_code` or
`recovery_code`. The evaluation order is fixed and each step is audited:

1. **Lockout.** A locked account returns `423 Locked` before the password is checked.
2. **Password.** A wrong password increments the failure counter and returns `401`.
3. **Second factor.** If the account has one enrolled and no code was supplied, the
   response is `401` with `MFARequiredResponse` — the client should prompt and retry. A
   wrong code is a `401`.
4. **Privileged policy.** An account holding `ADMIN` without a second factor is refused
   with `403`. This is the last check on purpose: it is the policy of last resort, and it
   fires even if the first three somehow passed.

`POST /api/auth/refresh` applies the same privileged check, so a session cannot be kept
alive past the point where the policy would have stopped it.

### Capabilities

`GET /api/auth/capabilities` publishes the role/capability matrix — useful for rendering
permissions and for auditing what each role can do. It describes policy; it grants nothing.
Authorization is always checked server-side against the same table, and the frontend uses it
only to hide controls.

| Capability group | ADMIN | SECURITY_ANALYST | ENGINEER | EXECUTIVE |
| --- | :-: | :-: | :-: | :-: |
| `org:read` | ✓ | ✓ | ✓ | ✓ |
| `org:write` | ✓ | | | |
| `member:read` | ✓ | ✓ | | |
| `member:write` | ✓ | | | |
| `scope:read` | ✓ | ✓ | ✓ | |
| `scope:write` | ✓ | ✓ | | |
| `asset:read` | ✓ | ✓ | ✓ | ✓ |
| `asset:write` | ✓ | ✓ | | |
| `scan:read` | ✓ | ✓ | ✓ | |
| `scan:create` | ✓ | ✓ | ✓ | |
| `finding:read` | ✓ | ✓ | ✓ | ✓ |
| `finding:write` | ✓ | ✓ | | |
| `remediation:write` | ✓ | ✓ | ✓ | |
| `report:read` | ✓ | ✓ | ✓ | ✓ |
| `report:generate` | ✓ | ✓ | | ✓ |
| `audit:read` | ✓ | ✓ | | |
| `graph:read` | ✓ | ✓ | ✓ | ✓ |
| `rule:read` | ✓ | ✓ | ✓ | |

Two notes on the shape of this table. `EXECUTIVE` deliberately lacks `scan:read`: an
executive sees outcomes — assets, findings, reports, the graph — not raw scanning activity.
And `ENGINEER` can write remediations but not findings, because an engineer's job is to
close the issue, not to adjudicate whether it is real.

## Endpoints

### Authentication — `/api/auth`

| Method | Path | Capability | Purpose |
| --- | --- | --- | --- |
| POST | `/login` | — | Authenticate; may require a second factor |
| POST | `/refresh` | — | Exchange a refresh token |
| GET | `/me` | authenticated | Current user, role, capabilities |
| GET | `/capabilities` | — | Role/capability matrix |
| GET | `/security` | authenticated | Own security posture: factors, lockout, last login |
| POST | `/mfa/totp/enrol` | authenticated | Begin TOTP enrolment; returns secret + provisioning URI |
| POST | `/mfa/totp/confirm` | authenticated | Confirm a code and activate the factor; returns recovery codes |
| POST | `/mfa/disable` | authenticated | Remove TOTP; refused if it is the last factor on a privileged account |
| POST | `/webauthn/register/options` | authenticated | Registration challenge |
| POST | `/webauthn/register` | authenticated | Complete registration |
| POST | `/webauthn/authenticate/options` | authenticated | Authentication challenge |
| POST | `/webauthn/authenticate` | authenticated | Complete authentication |
| DELETE | `/webauthn/credentials/{credential_id}` | authenticated | Remove a hardware key |

**There is no "enrol a factor for this user id" endpoint.** Every second-factor endpoint
acts on the caller's own account only. An administrator who could enrol a factor on someone
else's behalf could create a credential they control on an account they do not own, which
defeats the purpose of the factor.

### Scope Registry — `/api/scope`

| Method | Path | Capability |
| --- | --- | --- |
| GET, POST | `/` | `scope:read` / `scope:write` |
| GET, PATCH, DELETE | `/{entry_id}` | `scope:read` / `scope:write` / `scope:write` |

A created entry is `PENDING` and is not scannable. `PATCH` to `AUTHORIZED` is what makes it
scannable, and that transition is audited with the actor and timestamp. Fields cover
environment, owner, authorization status, who authorized it, when, an expiry, and
`allow_port_override`.

`DELETE` removes the entry outright, and the assets discovered under it are retained.
Deleting an authorization should not erase the evidence of what was found while it was
authorized — so the scan history and observations survive the entry that permitted them.
The deletion is audited. If you want to stop scanning a target while keeping the record of
its authorization, set the status to `REVOKED` instead.

### Scans — `/api/scans`

| Method | Path | Capability |
| --- | --- | --- |
| GET, POST | `/` | `scan:read` / `scan:create` |
| GET | `/{scan_id}` | `scan:read` |

`POST` resolves authorization freshly, then runs the scan **synchronously** and returns the
finished scan. There is no job queue and no worker; see
[DEPLOYMENT.md](DEPLOYMENT.md#there-is-no-worker) for the capacity implication.

Refused targets are returned on the scan with their reason rather than silently dropped. A
`port_override` is rejected with `400` unless *every* selected entry has
`allow_port_override` set — neither silently ignoring the parameter nor silently honoring
it would be acceptable.

### Assets — `/api/assets`

| Method | Path | Capability |
| --- | --- | --- |
| GET | `/` | `asset:read` |
| GET | `/{asset_id}` | `asset:read` |
| GET, PUT | `/{asset_id}/context` | `asset:read` / `asset:write` |
| POST | `/{asset_id}/rescore` | `finding:write` |

`PUT /context` is where business context is supplied. It is stored with provenance
`USER_PROVIDED`, and `internet_exposed` is a *claim by the organization*, distinct from the
observed `reachable` fact. Veyl will not assert that an asset is internet-exposed on the
customer's behalf.

### Findings — `/api/findings`

| Method | Path | Capability |
| --- | --- | --- |
| GET | `/` | `finding:read` |
| GET | `/{finding_id}` | `finding:read` |
| GET | `/{finding_id}/evidence` | `finding:read` |
| GET | `/{finding_id}/history` | `finding:read` |
| PATCH | `/{finding_id}/status` | `finding:write` |
| PUT | `/{finding_id}/remediation` | `remediation:write` |

`/evidence` returns the observations the finding was derived from, with the matcher that
fired, the provenance, and the confidence. This is the endpoint that makes the product's
claim checkable: a reader can see the bytes behind the conclusion.

`/history` returns the append-only event log for the finding.

### Changes — `/api/changes`

| Method | Path | Capability |
| --- | --- | --- |
| GET | `/` | `finding:read` |
| GET, PATCH | `/{change_id}` | `finding:read` / `finding:write` |

Exposure changes derived from snapshot diffs, classified risk-increasing / risk-reducing /
neutral.

### Graph and attack paths

| Method | Path | Capability |
| --- | --- | --- |
| GET | `/api/graph` | `graph:read` |
| POST | `/api/graph/rebuild` | `scope:write` |
| GET | `/api/attack-paths` | `graph:read` |
| GET | `/api/attack-paths/{path_id}` | `graph:read` |
| POST | `/api/attack-paths/recompute` | `scope:write` |

Rebuilds are idempotent — stable `node_key` values mean the same input produces the same
graph. **Attack paths are labelled "potential"**: they are hypotheses about reachability
derived from graph structure, not confirmed exploits, and the API does not claim otherwise.

### Rules — `/api/rules`

| Method | Path | Capability |
| --- | --- | --- |
| GET | `/` | `rule:read` |
| GET | `/{rule_id}` | `rule:read` |
| GET | `/meta/categories` | `rule:read` |

Served from the in-process registry, not the database. A rule is code; see
[DETECTION_RULES.md](DETECTION_RULES.md#adding-a-rule).

### Reports — `/api/reports`

| Method | Path | Capability |
| --- | --- | --- |
| GET, POST | `/` | `report:read` / `report:generate` |
| GET | `/{report_id}` | `report:read` |
| GET | `/{report_id}/download` | `report:read` |

HTML and JSON are implemented. **PDF returns `501 Not Implemented`** — deliberately, rather
than emitting a broken file.

### Members, audit, dashboard, health

| Method | Path | Capability |
| --- | --- | --- |
| GET, POST | `/api/members` | `member:read` / `member:write` |
| GET, PATCH, DELETE | `/api/members/{member_id}` | `member:read` / `member:write` |
| GET | `/api/audit` | `audit:read` |
| GET | `/api/audit/summary` | `audit:read` |
| GET | `/api/audit/verify` | `audit:read` |
| GET | `/api/dashboard` | `finding:read` |
| GET | `/api/health` | — |
| GET | `/api/health/ready` | — |

Granting `ADMIN` through `/api/members` is refused with `409` if the target account has no
second factor. A role whose policy cannot be satisfied is not granted.

`GET /api/audit/verify` walks the per-tenant hash chain and reports whether it is intact.

## Conventions

**Pagination.** List endpoints accept `limit` and `offset` with enforced bounds, and return
a `Page` envelope carrying the total. Bounds are validated rather than clamped, so an
out-of-range request is a `422` rather than a surprise.

**Errors.** FastAPI's standard shape: `{"detail": ...}`. `detail` is a string for simple
failures and an object when there is structure worth returning — the scan submission
refusal returns the list of refused targets with their individual reasons.

**Validation errors do not echo submitted values.** A `422` on a login or password field
will not repeat the password back in the response body.

**Tenant isolation.** Every query is filtered by the resolved organization. A resource
belonging to another tenant is a `404`, not a `403` — the existence of another tenant's
resource is not disclosed.

**Auditing.** Every state change writes an audit entry: scope authorizations, scans,
finding status transitions, remediations, member changes, report generation, and every
authentication outcome including failures and lockouts.

## Status codes used

| Code | Meaning here |
| --- | --- |
| 200 / 201 | success |
| 400 | malformed request the schema could not catch — no authorized scope, bad port override |
| 401 | bad credentials, missing/expired token, second factor required or wrong |
| 403 | authenticated but not permitted; privileged account missing a factor; wrong tenant claim |
| 404 | not found, or found in another tenant |
| 409 | conflict — granting `ADMIN` to an account with no second factor; removing a last factor |
| 422 | schema validation failure |
| 423 | account locked |
| 501 | PDF reporting, not implemented |

## Not implemented

Stated so nobody builds against them: PDF reports (`501`), scheduled scans, webhooks, bulk
import/export, an API-key (non-JWT) authentication mode, and any write endpoint for
observations or evidence — evidence is produced by collectors and is not client-writable by
design.
