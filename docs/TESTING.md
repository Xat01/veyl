# Testing

## Running

```bash
python -m pytest                    # 223 tests
python -m pytest tests/security -v  # the safety properties, verbose
python -m pytest -k ssrf            # by keyword
python -m pytest --tb=long -x       # stop at the first failure
ruff check .

python scripts/acceptance_test.py   # 35-step end-to-end run over HTTP (§47)
```

The acceptance test is separate from pytest on purpose. See
[the end-to-end test](#the-end-to-end-test) below.

Windows: if pytest hangs or errors during teardown with a bulk-delete complaint, that is
temp-directory cleanup, not a failing test.

```bash
python -m pytest --basetemp=./.pytest_tmp -p no:cacheprovider
```

## What the suite is for

The tests are not there to raise a coverage number. They exist because four properties are
what make this product trustworthy, and each of those properties is the kind that silently
stops being true:

1. **Veyl never scans what it was not authorized to scan.**
2. **Veyl never reaches an address the safety floor refuses.**
3. **Veyl never raises a finding it cannot evidence.**
4. **Veyl never lets an attacker quietly rewrite history.**

Everything else is ordinary correctness. Those four are the product.

## Layout

| File | Tests | Covers |
| --- | --- | --- |
| `tests/integration/test_api.py` | 109 | the full HTTP surface, auth, MFA, RBAC, tenant isolation |
| `tests/security/test_ssrf_floor.py` | 63 | address classification and every SSRF encoding |
| `tests/security/test_scope_enforcement.py` | 35 | authorization boundaries |
| `tests/security/test_audit_chain.py` | 10 | hash-chain integrity |
| `tests/unit/test_persistence_enums.py` | 6 | enum round-tripping, timezone handling |

Counts are collected tests; the `def test_` count is lower because several are
parametrized — the SSRF suite runs one case per attack vector.

## The end-to-end test

`scripts/acceptance_test.py` is not pytest, and that is deliberate. pytest is good at
"does this function do what it says"; it is bad at "does the product work when you use it".
The unit and integration suites had 223 passing tests and still missed a handler that
returned `500` on the most common action in the product.

So this script builds the demo environment, starts a real uvicorn server, and drives the
HTTP API in the order a person would: authorize a target, scan it, read the evidence,
supply business context, watch the risk score move, look at what changed, inspect the
graph, follow an attack path, assign a remediation, generate a report, verify the audit
chain.

```bash
python scripts/acceptance_test.py
python scripts/acceptance_test.py --keep-db   # inspect the database afterwards
```

Exit code is `0` only if every step passed. A step that cannot run is reported `SKIP` with
the reason and never counts as a pass — an unavailable test that silently reads as green is
how a suite rots.

It asserts the claims, not just the status codes: that every finding cites evidence, that
the risk score names its factors, that attack paths state their limitations, that a rebuild
is idempotent, that authorizing the cloud metadata address is not enough to scan it, and
that PDF reporting is `501` rather than a broken file.

**On the first run, 11 of 35 steps failed.** Ten were wrong expectations in the test — I
had guessed at response codes and field names instead of reading the schemas, and one
assertion was simply wrong about the product (I assumed an analyst could not read the audit
log; `SECURITY_ANALYST` is granted `audit:read`, so the test was wrong and the code was
right). The eleventh was a real defect. Each wrong expectation was corrected against the
actual schema rather than by relaxing the assertion, because a test that is loosened to pass
is worse than no test.



## The suites that matter

### SSRF floor — `test_ssrf_floor.py`

Parametrized over the encodings that defeat naive filters: decimal, hex, short form,
IPv4-mapped IPv6, NAT64, 6to4, and the cloud metadata endpoints. Each is asserted to be
refused.

Three tests are worth calling out:

- `test_no_ssrf_vector_is_ever_allowed` — a sweep asserting that no vector in the corpus
  gets through under default settings. If someone adds an encoding to the corpus and the
  floor does not catch it, this fails.
- `test_metadata_is_blocked_unconditionally` — metadata endpoints stay blocked even with
  `VEYL_ALLOW_PRIVATE_TARGETS=true`. The switch lifts private ranges; it does not open the
  credentials endpoint.
- `test_loopback_is_permitted_only_in_a_local_development_env` — the escape hatch is
  asserted to be exactly as narrow as intended, so it cannot quietly widen.

Also covered: injection characters in target strings, bare hostnames with no dot, and
`test_rejection_is_explainable` — every refusal carries a machine-readable reason, because
"blocked" with no explanation is indistinguishable from a bug.

### Scope enforcement — `test_scope_enforcement.py`

The boundary tests: a `PENDING` entry is refused with the *right reason*, a `REVOKED` one is
refused, an expired one is refused, an inactive one is refused, and an out-of-scope target is
refused.

- `test_domain_matches_is_label_aware` — authorizing `example.com` does not authorize
  `notexample.com` or `example.com.attacker.net`. This is the test that stops a suffix-match
  regression from becoming a scanning-someone-else's-infrastructure incident.
- `test_scope_does_not_leak_between_organizations` — one tenant's authorization is invisible
  to another.
- `test_ip_in_cidr` / `test_cidr_entry_authorizes_an_ip_target` — CIDR matching both ways.

The reason assertions matter as much as the refusals. A target refused for the wrong reason
tells an operator to fix the wrong thing.

### Audit chain — `test_audit_chain.py`

- `test_tampering_is_detected` — altering a historical entry breaks verification.
- `test_recomputed_hash_on_a_tampered_entry_still_breaks_the_link` — the important one. An
  attacker who edits a row *and* recomputes its own hash still breaks the chain, because the
  next entry's `prev_hash` no longer matches. This distinguishes a hash chain from a
  per-row checksum.
- `test_truncation_is_detected` — deleting the tail is detected.
- `test_chain_is_per_tenant` — chains do not interleave across organizations.
- `test_last_entry_hash_flushes_pending_rows` — a subtle one: an unflushed row would produce
  a chain that verifies but omits the most recent action.
- `test_hash_is_deterministic_and_key_dependent` and
  `test_canonicalisation_is_insensitive_to_key_order` — the hash is stable across key
  ordering but changes with the key, so it is not forgeable without the secret.

### Persistence — `test_persistence_enums.py`

Small but load-bearing.

- `test_every_enum_column_uses_enum_type` — a meta-test that walks the models and asserts
  every enum column uses the `EnumType` decorator. A plain `String` column would store
  `"Severity.HIGH"` instead of `"HIGH"` and break every comparison after a reload. This is
  the test that catches that class of mistake at the schema level rather than at runtime.
- `test_asset_reachable_and_internet_exposed_are_separate_facts` — encodes the architectural
  distinction that reachability is *observed* and internet exposure is *asserted by the
  customer*. Two columns, two provenances, and this test stops them being collapsed.
- `test_timestamps_are_timezone_aware_after_load` — a naive datetime from SQLite would
  silently compare wrong against an aware one.
- `test_is_authorized_now_works_after_db_load` — authorization logic that works on an
  in-memory object and fails after a reload is a real bug class.

### API — `test_api.py`

109 tests over the HTTP surface, including ~34 for §27 authentication hardening. The
notable ones:

- **Privileged-account policy** — login refuses, refresh refuses, and granting `ADMIN` to an
  account without a factor is a `409`. All three, because enforcing at one point is bypassed
  by the others.
- **`test_an_admin_cannot_disable_their_only_factor`** — this test found a real bug. The
  guard used a helper that short-circuits when the account already has a factor, so it never
  fired and an `ADMIN` could strip their own second factor. The test asserted `409` and got
  `200`. Fixed by checking the post-removal factor count instead.
- **WebAuthn refusals** — malformed attestation, wrong ceremony type, wrong origin, and
  replayed challenges each produce a specific error rather than a generic rejection.
- **Tenant isolation** — a resource in another organization is a `404`, not a `403`, so
  existence is not disclosed.
- **`test_validation_errors_do_not_echo_the_submitted_password`** — a `422` must not repeat
  the password back in the response body.
- **Scan authorization at submit time** — an expired entry cannot be scanned by submitting a
  request.

## Writing tests

**Assert the reason, not just the refusal.** `assert response.status_code == 400` passes for
the wrong reason too. `assert "expired" in response.json()["detail"]` fails when the
behavior drifts.

**Test both directions.** A rule or a guard needs a case that fires and a case that does
not. A rule with only a positive test has unknown false-positive behaviour, which is what
actually decides whether the tool is usable.

**Prefer the real object over a mock.** The scanner tests use a real HTTP server on
loopback; the API tests use a real SQLite database through the real session factory. A mock
of the thing you are testing mostly tests the mock.

**Do not weaken an assertion to make a change pass.** If a security test fails, the finding
is that the change broke a security property. Two of the bugs fixed during development were
found exactly this way. Fix the code.

## Fixtures

`tests/conftest.py` provides:

- `session` — a real SQLAlchemy session against a temporary SQLite database, with settings
  and the engine reset before and after each test, and the schema created and dropped
  around it.
- `admin` — an admin user with a real TOTP factor enrolled against a known secret, because
  §27 refuses to authenticate an admin without one.
- `two_tenants` — two organizations, each with a compliant admin, for isolation tests.
- A loopback HTTP server helper.

Helpers `totp_for()`, `login()`, and `login_as()` compute live TOTP codes, so no test
depends on a frozen clock or a pre-baked code.

Settings overrides in tests go through the `overridden_settings` context manager, which
validates keys against `Settings.model_fields` and restores on exit. Mutating
`os.environ` directly leaks between tests and produces failures that depend on order.

### `VEYL_ALLOW_PRIVATE_TARGETS` must be `true` for the suite to run

`conftest.py` establishes the test environment with `os.environ.setdefault(...)`. The
integration tests scan a real HTTP fixture bound to `127.0.0.1`, so they need
`VEYL_ALLOW_PRIVATE_TARGETS=true` — which conftest sets, but only if the variable is not
already present. **A value supplied by the environment wins.**

This caused a CI failure that looked like a product bug and was not one. The workflow set
the variable to `"false"`, so `setdefault` did nothing, the safety floor correctly refused
loopback, and fifteen integration tests failed on `assert scan["targets_scanned"] == 1`
returning `0`. The product was right; the workflow was wrong.

If you see mass failures that all trace back to zero targets being scanned, check this
variable before anything else:

```bash
echo "$VEYL_ALLOW_PRIVATE_TARGETS"     # must be true (or unset) for the suite
```

This does not weaken the SSRF coverage. The security suite asserts the refusal directly,
and `test_loopback_is_refused_in_a_public_deployment` overrides the setting itself rather
than depending on the ambient value.

## Coverage

`pytest-cov` is installed. Coverage is not enforced as a gate — a threshold produces tests
written to cross it. The suites above are organized around properties rather than lines, and
a property that is untested is a known gap rather than a number that looks fine.

## Continuous integration

Every push and pull request runs `ruff check .` and the full suite on Python 3.11, 3.12, and
3.13. See [.github/workflows/ci.yml](../.github/workflows/ci.yml).

## Known gaps

- The TLS and HTTP parsers are not fuzzed. They consume hostile input and are the largest
  untested attack surface in the codebase.
- The WebAuthn implementation has no interoperability test against a real browser or
  hardware key. It is verified against constructed assertions, which proves the signature
  logic and not the wire format against a real client.
- No load or concurrency testing. Scans run synchronously in the request, so behaviour under
  concurrent submissions is not characterized.
- The attack-path correlation has no test against a graph large enough to expose performance
  problems.
