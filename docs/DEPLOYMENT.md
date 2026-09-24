# Deployment

## Read this first

Two facts determine how you deploy Veyl, and both are capacity rather than correctness:

1. **Scans run synchronously inside the API request.** There is no worker and no queue.
2. **SQLite is the default database.** It is fine for evaluation and single-user use, and
   wrong for concurrent production use.

Neither is a security problem. Both are load-bearing for how you size the deployment, so
they are stated up front rather than buried.

## Local evaluation

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

python -m veyl_api.demo     # seed AcmePay, run the Day 1 -> Day 7 scans
python -m veyl_api          # http://127.0.0.1:8000
```

The demo sets a known password and enables private-range targets so it can scan its bundled
service on loopback. It prints both facts when it runs. Do not carry a demo database into
anything that matters.

## Configuration

Copy `.env.example` to `.env`.

### Required in any non-local deployment

| Setting | Why |
| --- | --- |
| `VEYL_SECRET_KEY` | Signs session tokens **and** derives the key that encrypts TOTP secrets. Generate with `python -c "import secrets; print(secrets.token_urlsafe(64))"`. Rotating it invalidates sessions and requires TOTP re-enrolment. |
| `VEYL_ENV=production` | Tightens defaults. Running production under `development` is a configuration error that the app cannot detect for you. |
| `VEYL_CORS_ORIGINS` | Your real console origin. WebAuthn validates origins against this list by exact match. |
| `VEYL_DATABASE_URL` | A Postgres URL. See below. |

### Must stay off in production

| Setting | Default | Why it must stay off |
| --- | --- | --- |
| `VEYL_ALLOW_PRIVATE_TARGETS` | `false` | Lifts the SSRF floor for private ranges. Enabling it in production defeats the control that stops Veyl being used to reach internal services and cloud metadata. |
| `VEYL_TRUST_PROXY_HEADERS` | `false` | Only enable behind a proxy you control that sets `X-Forwarded-For`. Otherwise client IPs — and therefore rate limiting and lockout attribution — are attacker-controlled. |
| `VEYL_NMAP_ENABLED` | `false` | Adds an external binary to the trusted computing base. |

### Worth tuning

| Setting | Default | Meaning |
| --- | --- | --- |
| `VEYL_SCAN_TIMEOUT_SECONDS` | `5.0` | per-probe timeout |
| `VEYL_SCAN_MAX_CONCURRENCY` | `64` | concurrent probes |
| `VEYL_SCAN_MAX_PORTS_PER_RUN` | `4096` | upper bound on a scan's port surface |
| `VEYL_ALLOWED_SCAN_PORTS` | `1-1024,3306,3389,5432,6379,8000-8100,8443,9000` | the port set a scan may touch |
| `VEYL_RATE_LIMIT_PER_MINUTE` | `120` | API rate limit |
| `VEYL_ACCESS_TOKEN_TTL_MINUTES` | `60` | session lifetime |
| `VEYL_REFRESH_TOKEN_TTL_DAYS` | `7` | refresh lifetime |
| `VEYL_ARTIFACT_DIR` | `./artifacts` | generated report storage |
| `VEYL_AI_ENABLED` | `false` | interpretation layer; off by default |

## Database

### SQLite (default)

No setup. Suitable for one user, evaluation, and demos. Two limits that matter: writes
serialize, and a scan holding a transaction blocks other writers. Do not run concurrent
scanning against SQLite.

### Postgres (recommended for production)

```bash
pip install -e ".[postgres]"
export VEYL_DATABASE_URL="postgresql+psycopg://veyl:password@localhost:5432/veyl"
```

Tables are created at startup if absent. **This is not a migration story.** Alembic is a
declared dependency and there is no migrations directory — schema changes are applied by
`create_all`, which adds missing tables and does nothing to existing ones. For a real
deployment, add Alembic revisions before you have data you care about. Until then, a schema
change means a fresh database.

### Backups

Back up the database, and treat the backup as sensitive: it contains the exposure map, the
audit chain, and encrypted TOTP seeds. **Losing the database loses the audit chain** — it
cannot be reconstructed, and a restored-from-nothing instance has no history to verify.

## Running the API

```bash
python -m veyl_api --host 0.0.0.0 --port 8000
```

Binds loopback by default. `--host 0.0.0.0` is the explicit statement that you want it
reachable. `--reload` is refused in combination with a non-loopback bind or a production
environment.

Behind a reverse proxy, terminate TLS there and forward to loopback. The API speaks plain
HTTP.

```nginx
server {
    listen 443 ssl;
    server_name veyl.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Only set `VEYL_TRUST_PROXY_HEADERS=true` when a proxy you control is actually setting those
headers.

## There is no worker

Scans execute inside the request that submits them. `POST /api/scans` blocks until the scan
finishes and returns the completed scan. For a handful of targets this is seconds.

**Why it is built this way.** The honest alternative was to enqueue the job and return
immediately. With no worker running, that presents as a scan that never completes — the user
sees a hang and no error, which is a worse failure than a slow response. Enqueueing without
a consumer would have been a feature that only appears to work.

**What this means operationally.**

- A scan of many targets holds an HTTP connection open and occupies a server worker. Set
  your proxy's read timeout accordingly, or scan in smaller batches.
- Concurrency is bounded by your server workers, not by `VEYL_SCAN_MAX_CONCURRENCY`.
- A restart mid-scan leaves that scan in `RUNNING` with no process behind it. It will not
  resume. Mark it failed and re-submit.
- There is no retry, no backoff, and no schedule.

**If you need a worker**, the shape is: a `jobs` table with a claim/lease column, a process
that claims a row and calls the same `ScanRunner`, and an API that writes the row and
returns `202` with a scan id in `RUNNING`. The runner already takes a session and a scan
object, so the work itself does not need to change. What must be added with it is the thing
that makes it honest: the API must refuse to accept a job when no worker has heartbeated
recently, otherwise you have rebuilt the silent hang.

## Containers

A `Dockerfile` and `docker-compose.yml` are provided under `infrastructure/docker/`.

**These have not been executed.** Docker is not installed in the environment this project
was developed in, so the images are unbuilt and untested — treat the first `docker compose
up` as the actual test, and expect to fix something. They are included because a deployment
path that has never been attempted is not a deployment path, but do not read their presence
as a verification.

What *is* verified is the application-level guard behind them. The settings model refuses to
construct under `VEYL_ENV=production` if any of three conditions holds, so a misconfigured
container fails at startup with a specific error rather than running insecurely:

- `VEYL_SECRET_KEY` is still the development default
- `VEYL_SECRET_KEY` is shorter than 32 characters
- `VEYL_ALLOW_PRIVATE_TARGETS` is true

All three were confirmed by constructing the settings object directly and observing the
refusal. The compose file reads the secret from the environment rather than baking one in.

Before using it in anything real:

1. Set `VEYL_SECRET_KEY` to a generated value.
2. Do not publish the Postgres port to the host in production.
3. Leave `VEYL_ALLOW_PRIVATE_TARGETS` unset.

## Deployment checklist

- [ ] `VEYL_SECRET_KEY` generated and set, and stored somewhere you can rotate from
- [ ] `VEYL_ENV=production`
- [ ] `VEYL_DATABASE_URL` pointing at Postgres
- [ ] `VEYL_CORS_ORIGINS` set to the real console origin
- [ ] `VEYL_ALLOW_PRIVATE_TARGETS` off
- [ ] `VEYL_TRUST_PROXY_HEADERS` only if a controlled proxy sets the headers
- [ ] TLS terminating in front of the API
- [ ] Database not reachable from the internet
- [ ] Database backups configured and the backups treated as sensitive
- [ ] At least one `ADMIN` enrolled with a second factor (the policy requires it, so verify
      it worked rather than assuming)
- [ ] An `EXECUTIVE` account for whoever needs reporting without scan access
- [ ] Scope entries registered, and only for assets you are authorized to test
- [ ] Log aggregation capturing the audit log
- [ ] A decision recorded about whether the console (`apps/web`, not built) is needed, since
      the API and HTML reports are the interface today

## Scaling notes

Ordered by what actually limits you first:

1. **Synchronous scans.** The first thing to break. Split scans across targets, or build the
   worker described above.
2. **SQLite write contention.** Solved by Postgres.
3. **Single API process.** The app is stateless apart from the database, so it scales
   horizontally — but each replica runs its own scans, so concurrency multiplies rather than
   queues.
4. **`observations` growth.** Every scan writes a full observation set per asset. This table
   grows fastest and is never pruned, because pruning it would break the evidence chain for
   historical findings. Plan retention deliberately: you can archive whole scans, but not
   individual observations referenced by a finding.

## Not implemented

PDF reports (`501`), scheduled scans, webhooks, a web console, agent-based collection, cloud
inventory, SSO/SAML, and database migrations. Each is absent rather than partially present.
See the Status section of the [README](../README.md).
