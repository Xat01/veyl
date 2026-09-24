# Detection Rules

37 rules across 8 categories. Every one is a deterministic function of stored
observations — no heuristics, no scoring models, no network calls at evaluation time.

## The rule contract

A rule declares five things beyond its identity, and the evaluator enforces them.

```python
RuleDefinition(
    rule_id="VEYL-WEB-001",
    title="Missing HTTP Strict Transport Security",
    category=RuleCategory.WEB,
    severity=Severity.MEDIUM,
    default_confidence=Confidence.HIGH,
    description="...",              # what this class of issue is
    detection="...",                # the exact condition, in words
    evidence_requirements=[...],    # observation kinds this rule may cite
    remediation="...",              # what to actually do
    check=check_missing_hsts,       # the pure function
    references=[...],
    requires=["http_security_headers"],   # kinds that must be present to run
    applies_when=None,              # optional applicability gate
    enabled=True,
)
```

**Rules have no I/O.** `check` receives a `RuleContext` — observations for a single asset
from a single scan — and returns `RuleMatch` objects. It cannot query the database, open a
socket, or read the filesystem. This is what makes a rule testable in isolation and
replayable against stored data.

**`requires` is a gate, not a hint.** If a required observation kind is absent, the rule is
*skipped* and the skip is recorded with a reason. A rule that never ran and a rule that ran
and found nothing are different outcomes, and the report distinguishes them. Otherwise a
missing collector silently looks like a clean result.

**`evidence_requirements` bounds what may be cited.** A match cannot cite an observation
kind the rule did not declare. A rule that could cite anything could cite something it
never read.

## The evidence contract

A `RuleMatch` is rejected — not stored, not shown — unless it supplies:

| Field | Meaning |
| --- | --- |
| at least one evidence reference | the observation(s) actually read |
| `matcher` | the condition that fired, in terms a human can check |
| `explanation` | why this observation means this finding |
| `impact` | what the business consequence is |

The evaluator reports rejections rather than dropping them, so a rule that is silently
failing its contract is visible instead of merely absent.

**The property this buys:** if a rule cannot point at an observation, it cannot raise a
finding. That is the whole basis for trusting the output, and it is enforced by code rather
than by reviewer discipline.

## Observation kinds

| Kind | Produced by | Contains |
| --- | --- | --- |
| `port_scan` | TCP connect scanner (or Nmap backend) | per-port state, latency |
| `service_fingerprint` | Fingerprinter | product, version, confidence, evidence |
| `tls_certificate` | TLS collector | subject, SAN, issuer, validity, self-signed flag, hostname validity |
| `tls_configuration` | TLS collector | negotiated protocol version, cipher suite, chain trust |
| `http_security_headers` | HTTP collector | response headers, redirect chain |
| `http_cookies` | HTTP collector | `Set-Cookie` values and parsed flags |
| `http_discovery_path` | HTTP collector | probed paths and their status/size |
| `http_response` | HTTP collector | status, headers, bounded body |
| `dns_record` | DNS collector | A/AAAA/CNAME/MX/TXT/NS |
| `subdomain` | DNS / CT collector | discovered names |
| `business_context` | the customer | criticality, data class, environment, exposure claim |

## Network — `VEYL-NET-*`

| Rule | Severity | Detection |
| --- | --- | --- |
| `VEYL-NET-001` | HIGH | Database service reachable from an untrusted position |
| `VEYL-NET-002` | MEDIUM | Administrative service reachable from an untrusted position |
| `VEYL-NET-003` | MEDIUM | Cleartext protocol exposed |
| `VEYL-NET-004` | INFO | Unclassified network listener |
| `VEYL-NET-005` | INFO | Wide open-port surface |

`NET-001` and `NET-002` fire on a port that convention associates with a database or an
administrative interface, but they do not assert the product on that basis. When the
fingerprinter confirmed the product, confidence is `HIGH` and the finding says "confirmed
as PostgreSQL". When it did not, confidence drops to `MEDIUM` and the wording changes to
"whose port is conventionally PostgreSQL" — because `5432` being open is evidence of a
database, not proof of which one. The evidence record carries the distinction, and the
reader can see which of the two they are looking at.

`NET-004` exists so that an unidentified listener is surfaced as unknown rather than
omitted; silence would read as "nothing there".

## TLS — `VEYL-TLS-*`

| Rule | Severity | Detection |
| --- | --- | --- |
| `VEYL-TLS-001` | HIGH | Expired TLS certificate |
| `VEYL-TLS-002` | MEDIUM | TLS certificate expiring soon |
| `VEYL-TLS-003` | MEDIUM | Self-signed TLS certificate |
| `VEYL-TLS-004` | MEDIUM | Certificate hostname mismatch |
| `VEYL-TLS-005` | MEDIUM | Deprecated TLS protocol version negotiated |
| `VEYL-TLS-006` | MEDIUM | Weak TLS cipher suite negotiated |
| `VEYL-TLS-007` | LOW | Certificate chain failed trust validation |

`TLS-007` is deliberately LOW and `TLS-003` (self-signed) is separate from it, because
"self-signed" and "untrusted chain" are different problems with different fixes. Collapsing
them would tell an operator to replace a certificate when the real issue is a missing
intermediate. The collector reports `self-signed`, `expired`, and `wrong hostname` as
independent facts for the same reason.

## Web — `VEYL-WEB-*`

| Rule | Severity | Detection |
| --- | --- | --- |
| `VEYL-WEB-001` | MEDIUM | Missing HTTP Strict Transport Security |
| `VEYL-WEB-002` | LOW | HSTS max-age below recommended baseline |
| `VEYL-WEB-003` | LOW | Missing Content Security Policy |
| `VEYL-WEB-004` | LOW | Permissive Content Security Policy |
| `VEYL-WEB-005` | INFO | Missing `X-Content-Type-Options` |
| `VEYL-WEB-006` | LOW | No clickjacking protection |
| `VEYL-WEB-007` | INFO | Missing `Referrer-Policy` |
| `VEYL-WEB-008` | INFO | Server version disclosed in response headers |
| `VEYL-WEB-009` | LOW | Cookie set without protective flags |
| `VEYL-WEB-010` | MEDIUM | Directory listing enabled |
| `VEYL-WEB-011` | CRITICAL | Publicly retrievable configuration or repository file |
| `VEYL-WEB-012` | MEDIUM | Error response discloses internal detail |

`WEB-011` is the highest-severity web rule and is intentionally narrow: it fires on a
*retrieved* file (`.env`, `.git/config`, backup and config artefacts), not on a guess that
one might exist. It reports a `200` with matching content, because that is the only thing
that constitutes evidence of retrievability.

## API — `VEYL-API-*`

| Rule | Severity | Detection |
| --- | --- | --- |
| `VEYL-API-001` | LOW | Potentially unsafe CORS configuration |
| `VEYL-API-002` | MEDIUM | API documentation publicly retrievable |
| `VEYL-API-003` | HIGH | Operational endpoint reachable without authentication |
| `VEYL-API-004` | INFO | API version prefix in active use |

`API-001` is LOW because a permissive CORS policy on a public, unauthenticated endpoint is
often correct. It is reported for review, not as a defect. `API-002` is MEDIUM for the same
reason it is not HIGH: exposed documentation is an information-disclosure finding, and
treating it as critical is how tools train operators to ignore severity.

## Authentication — `VEYL-AUTH-*`

| Rule | Severity | Detection |
| --- | --- | --- |
| `VEYL-AUTH-001` | HIGH | Sensitive interface reachable without an authentication challenge |
| `VEYL-AUTH-002` | HIGH | Data service reachable from the assessed position |
| `VEYL-AUTH-003` | INFO | Cross-host redirect |

`AUTH-001` and `AUTH-002` carry `MEDIUM` default confidence rather than `HIGH`. A `200`
response to an unauthenticated request is strong evidence, but a `200` login *page* is not
the same as a `200` from a protected resource, and the rule does not have enough context to
always tell. Confidence is a distinct axis from severity precisely so this can be expressed.

## Infrastructure — `VEYL-INFRA-*`

| Rule | Severity | Detection |
| --- | --- | --- |
| `VEYL-INFRA-001` | CRITICAL | Container or orchestration control plane exposed |
| `VEYL-INFRA-002` | LOW | Interactive API console served |

`INFRA-001` is CRITICAL because a reachable Docker daemon API or Kubernetes control plane is
generally equivalent to host compromise, not merely a finding to schedule.

## Exposure — `VEYL-EXP-*`

These are the rules that make the product an exposure tool rather than a scanner. They
combine a network fact with a business claim, which is why every one requires
`business_context` to run at all.

| Rule | Severity | Detection |
| --- | --- | --- |
| `VEYL-EXP-001` | CRITICAL | Business-critical asset is internet-reachable |
| `VEYL-EXP-002` | MEDIUM | Production asset exposes non-standard ports |
| `VEYL-EXP-003` | MEDIUM | Non-production asset exposed to the internet |
| `VEYL-EXP-004` | HIGH | Asset holding sensitive data is exposed |

**On `internet_exposed`.** Veyl *observes* that a host is reachable from the scanning
position. It does not conclude that the asset is published to the internet — that is a claim
only the owning organization can make, and only the organization knows whether a reachable
host is a deliberate public endpoint or a mistake. The field is `USER_PROVIDED`, and these
rules read the customer's assertion rather than inferring one. Reachability and internet
exposure are kept as separate concepts throughout the codebase for exactly this reason.

## Severity and confidence are different axes

Severity answers *how bad if real*. Confidence answers *how sure are we it is real*. They
are separate fields, separate weights in the risk model, and separate columns in the UI.

A HIGH-severity, MEDIUM-confidence finding is a different object from a MEDIUM-severity,
HIGH-confidence one, and a list that sorts them together is lying about what it knows. The
risk model caps confidence's contribution at 8 points precisely so it can never promote a
low-confidence finding above a confirmed one.

## What no rule does

- **No CVE is invented.** A CVE is attached only when a fingerprinted version falls inside
  a known affected range. Product-name similarity is never sufficient. A CVE mapping
  requires `service_fingerprint` evidence with a concrete version.
- **No version is guessed.** If the fingerprint is inconclusive, the version is reported as
  unknown. Rules that need a version are *skipped* with a reason, not run against a
  plausible guess.
- **No rule fires without evidence.** Enforced by the contract above.
- **No rule reaches the network.** Enforced by the absence of any client in the rule
  framework's imports.

## Adding a rule

1. Write the `check` function as a pure function of `RuleContext`.
2. Declare `requires` (must be present to run) and `evidence_requirements` (may be cited).
3. Fill in `detection` with the condition in words a human can verify against the evidence.
4. Fill in `remediation` with something actionable, not "apply best practices".
5. Register it in the category module's list.
6. Add a test with a fixture observation that matches and one that does not. A rule with
   only a positive test is a rule whose false-positive behaviour is unknown.

Rules are code, and the catalogue endpoint serves them from the in-process registry rather
than from the database. A rule is a function; storing a copy of its metadata in a table
would create two sources of truth that could disagree about what a rule does.

There is a `rule_definitions` table in the schema that mirrors rule metadata, intended so
that a historical finding stays interpretable after a rule is retired or rewritten.
**Nothing currently writes to it.** It is unused, and the finding record does not depend on
it: a finding stores the rule id, and the rule text is resolved from code at render time.
That means editing a rule changes how a past finding is explained. If you need findings to
be explainable by the rule text as it read when they were raised, this table has to be
populated at evaluation time — it is the intended place for that, and it is not wired up.
