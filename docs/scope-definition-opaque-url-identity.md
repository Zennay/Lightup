# Durable asset entries never derive URL authority

Issue: #372

`ScopeDefinition.assets` and `excluded_assets` are durable authorization inputs, not URL-to-host authority derivation rules.

## Locked invariants

- A scheme-bearing asset entry cannot authorize its embedded hostname.
- Userinfo, port, path, query, fragment, and network-path decoration cannot derive plain-host authority.
- A future stricter constructor may reject URL-like asset text entirely; this contract treats that as valid authority narrowing.
- If URL-like text remains representable as an opaque asset identifier, it still cannot authorize a different plain-host identity by parsing or decoration.
- URL-like exclusions cannot parse or pattern-match a distinct plain-host identity.
- Existing exact case/whitespace normalization for canonical plain assets remains unchanged.

This contract intentionally does **not** require URL-like asset text to remain positively accepted. It is separate from #367, which covers the direct `ScopePolicy.explicit_hosts` configuration layer, and from #369/#370, which cover wildcard/suffix expansion and set semantics for the durable asset layer.

## Safety boundary

These regressions are pure in-memory authorization evaluation. They perform no DNS resolution, socket/HTTP I/O, scanning, target interaction, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
