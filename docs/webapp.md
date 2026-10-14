# Web shell (M1 skeleton)

`lightup serve` (or `python -m lightup.webapp`) runs a dependency-free,
server-rendered web shell over the domain store.

## Surfaces

- **Operator/admin** — `/` (Overview), `/discovery`, `/clients`, `/assessments`.
- **Client portal** — `/portal/<client_id>`: findings as
  *Finding → Impact → Fix → Retest*, request status, and an assessment-request
  form. No scanner terminology, no raw tool output.

## UI rules applied

- Status/outcome first; technical detail behind `<details>` expanders.
- One primary action per screen; destructive/secondary actions styled down.
- Prospect cards show company, potential exposure, confidence and
  **Active testing: Locked** — nothing else at the first level.
- Small navigation: Overview / Discovery / Clients / Assessments.

## Security posture of this phase

- **Every page requires a signed-in session.** Passwords are scrypt-hashed with
  per-user salts; session tokens are stored server-side only as SHA-256 hashes
  with an expiry; a password change revokes all sessions. Bootstrap the first
  account with `lightup create-operator`, client accounts with
  `lightup create-client-user`.
- Admin pages require an operator session; the portal requires a session of
  that client (or an operator viewing read-scoped as that client).
- Authenticated POSTs require the session's CSRF token; the cookie is `HttpOnly`
  and `SameSite=Strict`. Logout revokes the current server-side session before
  clearing the cookie. Successful sign-in replaces an existing session; other
  browser sessions are unaffected.
- POST bodies must be fixed-length URL-encoded forms, at most 64 KiB and 64
  fields. Malformed framing/UTF-8/percent escapes, duplicate keys, truncated
  bodies and unsupported media types are rejected before session lookup or
  domain mutations.
- Authorization-bearing forms fail closed on ambiguity: grant/request risk must
  be an explicit canonical level 1–4, grant validity must be an explicit
  whole-number 1–365 day window, and approval/denial controls accept only their
  exact enumerated decision values. Missing or malformed authority fields never
  receive defaults and do not mutate durable request, approval, or grant state.
- Tenant isolation is additionally enforced in `lightup.domain`
  (`AccessContext`), not in templates; the portal physically cannot query
  another client's rows even if the UI layer were wrong.
- No route can trigger target interaction. The web layer only reads/writes the
  domain store; active execution stays behind the (still disabled) activation
  gate and execution policy.
- All dynamic output is HTML-escaped. Every response (including redirects and
  errors) uses `Cache-Control: no-store` to keep findings and session-bearing
  forms out of shared caches. CSP denies framing and base-URL injection, and
  permits form submissions only to the same origin; `X-Frame-Options: DENY`
  also protects older browsers.
- The dev server binds to loopback and speaks HTTP. The separate production
  factory enforces an explicit HTTPS origin and local proxy, checks Host and
  POST Origin (including login), and sets Secure cookies and HSTS. See
  `docs/deployment.md` for the Gunicorn/Nginx/systemd deployment package.

## Later

Operator RBAC granularity, password reset flows, rate limiting on login, and a
richer front-end can replace this shell without touching the domain layer.
