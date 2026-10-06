# Durable asset scope is exact

Issue: #369

`ScopeDefinition.assets` and `excluded_assets` are durable authorization boundaries. Their current contract is **exact normalized membership**, not wildcard, suffix, parent-domain, or child-domain inheritance.

## Locked invariants

- `example.test` does not authorize `api.example.test`.
- `*.example.test` is literal policy text; it does not authorize a concrete subdomain.
- `.example.test` is literal policy text; it does not authorize descendants.
- Child and parent asset identities do not inherit authority in either direction.
- Suffix/lookalike hosts such as `example.test.attacker.test` remain outside the allowlist.
- Existing trim/lower normalization remains valid for exact identities.
- Wildcard-looking exclusions are literal too; they do not remove a different concrete asset by pattern.

This contract is intentionally separate from ScopePolicy explicit-host handling (#286) and from canonicalization work owned by #117/#151. It does not change trailing-dot or IP canonicalization semantics.

## Safety boundary

The regression is pure in-memory authorization evaluation. It performs no DNS resolution, socket/HTTP I/O, scanning, target interaction, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
