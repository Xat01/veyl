# Veyl web console

A single-page console for the Veyl API. Plain HTML, CSS, and ES2020 — **no build
step, no `node_modules`, no bundler**.

It is served by the API itself at `/console/`, so evaluating the product is one
process:

```bash
python -m veyl_api.demo     # seeds data and prints credentials
python -m veyl_api          # then open http://127.0.0.1:8000/console/
```

## Why not Next.js

An earlier draft of the specification called for a Next.js application. This is
not that, and the difference is deliberate rather than an omission:

- **One origin.** The console is served from the same origin as the API, so
  there is no CORS configuration to get wrong, no second auth implementation,
  and no token-in-a-cookie-versus-header debate.
- **No toolchain.** `pip install -e ".[dev]"` is the only install. A reviewer
  does not need Node, a lockfile, or a network round-trip to a package registry
  to look at the product.
- **Small enough to audit.** Three files, no dependencies. In a security tool,
  a dependency-free client is a feature: there is no supply chain to trust.

The trade-offs are real: no server-side rendering, no component library, no
routing beyond `location.hash`, and no automated accessibility audit. For a
console that an analyst opens on a laptop, those are acceptable. For a
multi-tenant SaaS front end they would not be.

## Files

| File | Contents |
| --- | --- |
| `index.html` | Shell: sign-in form and the application frame. No inline script or style. |
| `styles.css` | All styling. Dark by default; the design tokens are at the top. |
| `app.js` | API client, hash router, and one render function per view. |

## What it does

| View | Reads | Writes |
| --- | --- | --- |
| Dashboard | `/dashboard` | — |
| Findings | `/findings`, `/findings/{id}` | status change, remediation assignment |
| Assets | `/assets`, `/assets/{id}` | recompute risk scores |
| Scope registry | `/scope` | add a target (authorization is explicit) |
| Exposure changes | `/changes` | acknowledge |
| Attack paths | `/attack-paths` | — |
| Scans | `/scans` | run a scan |
| Reports | `/reports` | generate, download |
| Audit log | `/audit`, `/audit/verify` | — |

Every write is gated on the capability the server publishes at `/auth/me`.
Hiding a control is cosmetic — the API re-checks the capability on every
request, so a console that lies about permissions changes nothing.

## What it deliberately does not do

- **No member management UI.** The endpoints exist (`/members`); the console
  does not expose them yet.
- **No WebAuthn enrolment UI.** Registering a hardware key needs a browser
  ceremony (`navigator.credentials.create`); the API side is implemented and
  tested, the ceremony is not wired into this page.
- **No scope deletion or editing.** Adding a target is supported; revoking one
  is an API call, because a destructive action deserves a confirmation flow
  that does not exist yet.
- **No realtime updates.** Data refreshes when a view is opened, not on a
  push channel.

## Security notes

- The access token is kept in `sessionStorage`, not `localStorage`: it dies with
  the tab and is not shared between tabs.
- The console is served with a Content-Security-Policy of
  `default-src 'self'` with no `unsafe-inline` or `unsafe-eval`. That is why
  there is no inline `<script>` or `style=` attribute anywhere in these files —
  adding one will break the page, by design.
- Everything the API returns is escaped before it reaches `innerHTML`. Banners,
  TLS subjects, and evidence detail are attacker-influenced in a security tool.
- The TOTP helper on the sign-in screen computes a code from a secret you paste
  in. It exists so the demo administrator can be signed into without an
  authenticator app; the arithmetic happens in the page and nothing is sent
  anywhere. It is not a credential store and should not be used as one.

## Verifying it

`scripts/console_e2e.mjs` drives this page in a real headless Chrome over the
DevTools Protocol: it signs in as an analyst, opens every view, changes a
finding's status, saves a remediation, starts a scan, generates a report, then
signs in as the administrator through the TOTP path. See
[docs/TESTING.md](../../docs/TESTING.md).
