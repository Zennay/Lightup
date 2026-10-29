# Session-authenticated CSV downloads

`lightup.webapp.finding_exports.create_app_with_exports(store, security=None)`
returns the existing web shell with a small CSV download extension. It inherits
the normal Host/Origin/transport validation, session lookup, portal tenant
checks, CSRF enforcement for existing POST routes and security response headers.
It does not override WSGI request validation or authentication.

Added GET routes:
- `/portal/CLIENT_ID/findings.csv`
- `/portal/CLIENT_ID/engagements/ENGAGEMENT_ID/findings.csv`

The portal displays one Download CSV link beside Findings. Downloads use
the tenant selection service merged in #959 with the original authenticated
context. Operators select one client; client users can access their own client
only. Engagement ownership and every returned finding are checked again.
Export failures return generic errors without partial CSV.

Downloads carry `text/csv; charset=utf-8`, a fixed attachment filename,
`Cache-Control: no-store`, nosniff and the normal restrictive CSP/frame headers.
Production HSTS remains provided by the inherited WSGI boundary.

This package is an optional factory; the default app/deployment entry point is
not switched. A caller can choose the new factory after its normal database
and WebSecurity setup. No target action, active testing route, model call,
authorization grant or security verdict is created. Existing app.py and other
workers' source files are untouched.

The full existing web suite remains part of standard CI; eleven new WSGI
regressions cover live/revoked sessions, client/operator ownership, corrupted
lineage, engagement mismatch, exact route spelling, no POST mutation route,
download headers, portal link and production trust-boundary rejection.
