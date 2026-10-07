# Scope authorization: ambiguous session cookies

Issue: #686

## Contract

Authorization must consume one unambiguous browser-session credential.

The WSGI request may contain unrelated cookies, but the exact `lightup_session` cookie name may occur at most once. Repeating it is ambiguous input and must fail closed before durable session lookup, regardless of whether the duplicate values differ or are byte-for-byte identical.

## Why this matters

`LightUpWebApp._authenticate()` currently delegates the complete raw `HTTP_COOKIE` string to `http.cookies.SimpleCookie` and then asks for one `lightup_session` morsel. Duplicate cookie names are therefore collapsed by a generic parser before authorization sees them.

When multiple valid session tokens are supplied, parser selection can choose which account identity reaches route authorization. The application should not derive operator/client authority from an ambiguous credential header.

## Acceptance

- one valid `lightup_session` retains existing authentication and authorization behavior;
- unrelated cookies, including names that merely contain `lightup_session` as a substring, may coexist with that one exact session cookie;
- two different `lightup_session` occurrences fail closed across normal semicolon-separated and comma-combined header forms;
- two identical `lightup_session` occurrences also fail closed;
- rejection happens before `DomainStore.session_context()`;
- ambiguous GETs resolve as unauthenticated and redirect to `/login`;
- rejection does not revoke or otherwise mutate either referenced live session.

## Current expected state

Against current `main`, duplicate-cookie cases are expected RED. `SimpleCookie` accepts both semicolon-separated duplicates and comma-combined duplicate header forms, exposes one selected morsel under `lightup_session`, and `_authenticate()` passes that value to `session_context()`.

The single-session, unrelated-cookie and exact-name controls are expected green.

## Collision boundary

This branch adds only:

- `tests/test_scope_authorization_session_cookie_ambiguity.py`;
- this contract document.

It does not modify:

- `src/lightup/webapp/app.py`, owned by active web authorization/input PR #182;
- cookie credential redaction owned by #671/#672, #674/#675 and #677;
- durable access/session reconstruction owned by #670;
- scope, activation, execution, workers, evidence-remediation, deployment, verdict or attack-path state.

The eventual source repair should reject duplicate occurrences in the raw cookie header before generic cookie-name collapsing and before calling `session_context()`.

## Safety

Offline request-authentication/authorization proof only. No target interaction, scanning, grant mutation, active execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
