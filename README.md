# Veyl

**Continuous Exposure Intelligence** — Know what your business exposes. Understand why it matters. Fix what actually puts you at risk.

> Status: work in progress. See [README.md](README.md) for what is implemented today
> versus what is explicitly **NOT IMPLEMENTED**.

## Repository layout

```
apps/web            Next.js analyst + executive console
apps/api            FastAPI application (HTTP layer only)
packages/rules      Deterministic detection rule definitions + engine
packages/schemas    Shared Pydantic contracts (API <-> scanner <-> rules)
services/scanner    Authorized discovery: DNS, ports, TLS, HTTP
services/analyzer   Rule evaluation -> findings + evidence
services/correlation  Change detection, graph, attack paths
services/worker     Background job runner
demo                AcmePay fictional demo environment
```

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
veyldb init && veyl-api            # API on :8000
```

Frontend:

```bash
cd apps/web && npm install && npm run dev   # :3000
```

Docker:

```bash
docker compose up --build
```

## Security

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
Veyl only ever scans assets that have been explicitly registered in the Scope Registry
with a valid authorization record.
