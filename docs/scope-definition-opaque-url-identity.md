# Durable asset entries stay opaque

Issue: #372

`ScopeDefinition.assets` and `excluded_assets` are durable asset identifiers. They are compared as exact normalized text and are not URL parsers or host-authority derivation rules.

## Locked invariants

- A scheme-bearing asset entry does not authorize its embedded hostname.
- Userinfo, port, path, query, fragment, and network-path decoration do not derive plain-host authority.
- URL-like asset text can remain an opaque exact asset identifier when the exact normalized text is queried.
- URL-like exclusions do not parse or pattern-match a distinct plain-host identity.
- Existing exact case/whitespace normalization for plain assets remains unchanged.

This contract is separate from #367, which covers the direct `ScopePolicy.explicit_hosts` configuration layer, and from #369/#370, which cover wildcard/suffix expansion and set semantics for the durable asset layer.

## Safety boundary

These regressions are pure in-memory authorization evaluation. They perform no DNS resolution, socket/HTTP I/O, scanning, target interaction, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
