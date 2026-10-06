# Scope authorization excluded-asset precedence

Issue: #343

This branch-only proof freezes the durable `ScopeDefinition` exclusion semantics
without modifying the active authorization/domain implementation.

## Contract

- Membership in `excluded_assets` overrides membership in `assets`.
- Both sides of the comparison use the existing trim/lower normalization.
- An exclusion for one asset does not deny a distinct allowed asset.
- An exclusion is deny-only; it never grants an asset that is absent from
  `assets`.

This matters because downstream authorization code can treat a persisted scope
as an allow/deny boundary. A deny entry must never be weakened by formatting
differences or by its simultaneous presence in the allowlist.

## Safety boundary

The proof performs no DNS or network I/O, target interaction, scanning,
capability execution, remediation/retest execution, deployment, or attack-path
mutation. It adds no execution authority.

## Collision boundary

Only these new files belong to this slice:

- `tests/test_scope_authorization_excluded_asset_precedence.py`
- `docs/scope-authorization-excluded-asset-precedence.md`

No existing source or test file is modified.
