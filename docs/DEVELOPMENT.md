# Development

## Requirements

- **Python 3.11+** (developed on 3.13)
- **Git**
- Optional: Node 18+ if you are working on the console, Postgres if you need it

**Not required:** Docker and Nmap are both optional. The default TCP connect scanner needs
neither, and the API runs against SQLite out of the box. This is deliberate — the product
should be runnable on a fresh machine without a container runtime, because a security tool
nobody can start is a security tool nobody evaluates.

## Setup

```bash
git clone https://github.com/Xat01/veyl.git
cd veyl

python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

`-e` matters: the monorepo maps several top-level packages to directories that are not
siblings, and `pyproject.toml`'s `[tool.setuptools.package-dir]` is what makes them
importable. A plain `pip install .` copies rather than links and you lose edit-reload.

Optional extras:

```bash
pip install -e ".[postgres]"    # psycopg for Postgres
pip install -e ".[nmap]"        # python-nmap adapter (still needs the nmap binary)
```

## Running it

```bash
python -m veyl_api.demo         # seed AcmePay and run the Day 1 -> Day 7 scans
python -m veyl_api              # API on http://127.0.0.1:8000
```

The demo prints the credentials and the admin's TOTP secret. Both commands are also
installed as console scripts (`veyl-demo`, `veyl-api`).

Reset the demo database at any time with `--reset`. It is a SQLite file, safe to delete.

## Tests

```bash
python -m pytest                       # everything
python -m pytest tests/security -v     # the safety properties
python -m pytest -k ssrf               # by name
ruff check .                           # lint
ruff check --fix .                     # autofix
```

223 tests. The suite is fast enough to run on every save; most of it is unit and API tests
with no network. The tests that do open sockets bind loopback only.

**On Windows, if pytest hangs or fails during teardown** with a bulk-delete error, it is the
temp-directory cleanup rather than a test failure. Redirect the base temp directory:

```bash
python -m pytest --basetemp=./.pytest_tmp -p no:cacheprovider
```

`.pytest_tmp/` is gitignored.

## Layout, and why it is shaped this way

```
apps/api/veyl_api/
  api/routes/        one module per resource; no business logic
  db/                Base, mixins, session lifecycle
  safety/            firewall (SSRF) and scope guard
  security/          auth, mfa, webauthn, sanitize
  models.py          all tables in one module
  enums.py           shared enumerations
  config.py          settings
  demo/              the AcmePay builder

packages/rules/veyl_rules/
  framework.py       rule contract, RuleContext, evidence validation
  registry.py        catalogue + evaluator + contract enforcement
  *_rules.py         rule definitions by category

services/scanner/    collectors: dns, portscan, tls, http, fingerprint
services/analyzer/   rule evaluation -> findings; risk model
services/correlation/ snapshots, graph, attack paths
services/reporting/  HTML and JSON renderers

demo/targets/        the AcmePay service the demo scans
tests/               unit, integration, security
```

Two conventions worth knowing before you edit anything:

**Every importable package is one or two directories deep, and the intermediate directories
are not packages.** `services/scanner/veyl_scanner/` has no `__init__.py` in `services/` or
`services/scanner/`. This is intentional — it keeps the import name (`veyl_scanner`)
decoupled from the path — and it means adding a package requires a matching entry in
`pyproject.toml` under both `packages` and `package-dir`.

**Keys in `[tool.setuptools.package-dir]` must be quoted.** TOML reads a bare
`veyl_api.api = "..."` as a nested table `veyl_api -> api`, which collides with the
`veyl_api` key. The error only appears when the file is parsed, so it fails at install time
rather than at edit time.

## Architectural rules

These are the constraints that keep the product's claims true. They are not style
preferences.

**Collectors observe; rules judge.** A collector writes `ObservationPayload` and nothing
else. It does not create findings, does not decide severity, and never sees an unauthorized
target. If you find yourself wanting a collector to raise a finding, what you actually want
is a new rule.

**Rules are pure.** A `check` function receives a `RuleContext` and returns matches. No
database session, no socket, no filesystem, no clock beyond what the context carries.
`packages/rules/veyl_rules/framework.py` imports only `collections.abc`, `dataclasses`,
`typing`, and `veyl_api.enums` — no HTTP client, and it should stay that way. That import
list is what makes the "rules cannot invent evidence" claim structurally true rather than
merely intended.

**Every match cites evidence.** The evaluator rejects a match with no evidence, a cited
observation kind absent from the context, no matcher, no explanation, no impact, or no
summary. See `_validate_match` in `registry.py`. Do not relax it to make a rule pass; if a
rule cannot cite evidence, the rule is wrong.

**Unknown beats wrong.** Do not add a fallback that guesses a version, a product, or a CVE.
If a fingerprint is inconclusive, the version is unknown and rules that need it are skipped
with a reason. `VEYL-NET-001` is the model to follow: when the product is unconfirmed it
drops to `MEDIUM` confidence and changes its wording to "whose port is conventionally X".

**Authorization is re-checked at submit time.** Not only at scope-entry creation. The gap
between registering a target and scanning it can be months, and an expiry has to matter.

**A scan never silently drops a target.** Refusals are recorded with a reason and returned.
A target that quietly disappears looks like a target that was clean.

**Never build a shell command from user input.** Sockets by default; `subprocess` with
`shell=False` and a list of validated arguments when an external tool is unavoidable.

## Adding things

### A detection rule

1. Write `check(context) -> list[RuleMatch]` as a pure function.
2. Declare `requires` (kinds that must be present to run) and `evidence_requirements`
   (kinds that may be cited).
3. Fill in `detection` as the condition in words a human can check against the evidence.
4. Fill in `remediation` with something actionable.
5. Register it in the category module's list.
6. Test both directions: a fixture that matches, and one that does not. A rule with only a
   positive test has unknown false-positive behaviour, which is the property that actually
   decides whether the product is usable.

See [DETECTION_RULES.md](DETECTION_RULES.md).

### A collector

Implement the `Protocol` in `veyl_scanner/contracts.py` — it is a Protocol rather than an
ABC so a new backend only has to *look* right and nothing downstream learns which one is
running. Emit observations. Do not import from `veyl_rules`.

If your collector resolves a hostname, resolve it through `validate_target` and **dial the
validated address**, not the name. That is what closes the rebinding gap.

### A database table

Add the model to `models.py`, inherit `OrgScoped` if it is tenant data, and use `EnumType`
for enums — it stores `.value` and resolves the class lazily from a
`"veyl_api.enums:ClassName"` string, so the model module does not have to import the enum
module at class-definition time.

## Debugging

**`no such table`** — the schema was not created. `create_all(engine)` runs at startup and
in the test fixtures; if you are in a REPL, call it yourself. Check you are pointed at the
database you think you are: `python -c "from veyl_api.config import settings; print(settings.database_url)"`.

**`DetachedInstanceError`** — you read an attribute from an ORM object after its session
closed. Return plain data across a session boundary rather than instances; a commit expires
attributes, so the first attribute access after a close will try to reload and fail.

**Settings changes not taking effect** — settings resolve at call time, not import time, so
`importlib.reload` is not needed and will not help. In tests use the `overridden_settings`
context manager, which validates keys against `Settings.model_fields` and restores on exit.

**A scan returns nothing** — check the refusals on the scan object first. A target with an
expired authorization, a deactivated entry, or an address the safety floor rejects is
refused rather than scanned, and the reason is on the scan.

**Fingerprint says `unknown`** — this is a valid result, not a bug. It means the evidence
did not support a conclusion. Do not "fix" it by guessing.

## Commits

Logical commits that each leave the tree working. Commit messages explain *why*: the
constraint that forced the change, or the failure that revealed it. "Update file" is not a
message; "require a second factor for privileged accounts, because enforcing only at login
is bypassed by extending a session" is.

Only commit working code. Run `pytest` and `ruff check .` before you commit.
