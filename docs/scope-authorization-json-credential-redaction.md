# Scope authorization quoted-credential redaction

## Boundary

Structured diagnostics often serialize credential fields as quoted JSON or
JSON-like key/value pairs. Those values must not survive LightUp's central
redaction boundary merely because the credential key itself is quoted.

The redactor covers quoted string values for:

- `access_token`, `refresh_token`, `id_token`, `auth_token`;
- `client_secret` and `api_key`;
- standalone `token`, `secret` and `password`.

Key spelling, key quotes, colon spacing and value quotes remain visible.
Escaped characters inside the original credential value are consumed as part of
the secret so no credential fragment is retained. Neighboring non-credential
fields stay unchanged.

## Safety properties

This is defensive text sanitization only. It does not parse a credential for
authentication, validate a grant, widen scope, alter activation, invoke a
target, or change remediation/retest authority.

The slice is stacked after the existing authorization-header, URL-userinfo,
cookie, compound-assignment and arbitrary-auth-scheme redaction boundaries.
