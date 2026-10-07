# Scope authorization compound-credential redaction

## Boundary

Credential fields often use compound names that are not covered by standalone
`token` or `secret` matching. LightUp must therefore remove values assigned
to these common keys at the central defensive text boundary:

- `access_token` / `access-token`
- `refresh_token` / `refresh-token`
- `id_token` / `id-token`
- `auth_token` / `auth-token`
- `client_secret` / `client-secret`

The key remains visible for diagnostics. Only its assigned value is replaced
with `[REDACTED]`. Query-string tails after `&` are preserved so unrelated
parameters remain observable.

## Safety properties

This change only sanitizes text. It does not validate credentials, authenticate
a caller, modify grants, expand scope, change activation, invoke a target, or
alter remediation/retest authority.

It is stacked after the authorization-header, URL-userinfo and cookie-session
redaction slices so each credential boundary stays independently reviewable.
