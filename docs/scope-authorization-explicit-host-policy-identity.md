# Explicit-host policy entries are host identities, not URLs

Issue: #367

## Contract

`ScopePolicy.explicit_hosts` is an exact host-identity allowlist. Target values may be URL-shaped because `ScopePolicy.normalize_host()` extracts the target authority host, but policy entries themselves are not URL inputs and must not be reinterpreted as URLs.

A policy entry therefore does **not** grant authority merely because an allowlisted-looking hostname appears inside:

- a scheme-qualified URL;
- userinfo;
- a `:port` suffix;
- a path;
- a query;
- a fragment; or
- a network-path reference such as `//host`.

This keeps the configuration boundary narrower than the target parser. A future refactor must not make `explicit_hosts` silently accept URL-like policy strings, because doing so would change stored policy text into new host authority.

## Positive control

Existing canonical behavior remains unchanged for a plain host identity: case folding and a trailing DNS dot still normalize for matching, and ordinary decoration on the **target** side still resolves to that same canonical host.

## Boundaries

This contract is intentionally separate from #267, which constrains parsing of the target URL. It also does not change wildcard/suffix semantics owned by #286 or percent-encoded target semantics owned by #366.

The regression is pure and in-memory. It does not perform DNS resolution, socket/HTTP I/O, scanning, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
