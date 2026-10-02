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

- **No authentication exists yet.** The server therefore refuses to bind to
  anything but a loopback address. Do not reverse-proxy it to a network until
  the auth package lands.
- Tenant isolation is enforced in `lightup.domain` (`AccessContext`), not in
  templates; the portal physically cannot query another client's rows.
- No route can trigger target interaction. The web layer only reads/writes the
  domain store; active execution stays behind the (still disabled) activation
  gate and execution policy.
- All dynamic output is HTML-escaped and responses carry a restrictive CSP.

## Later

Authentication/sessions, operator RBAC, CSRF tokens for the form posts, and a
richer front-end can replace this shell without touching the domain layer.
