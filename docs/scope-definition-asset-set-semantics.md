# Durable asset membership has set semantics

Issue: #370

Durable `ScopeDefinition` asset authorization is independent of tuple ordering and duplicate count. Authority is determined only by exact normalized membership in the allowlist and absence from the exclusion set.

## Locked invariants

- Reordering `assets` does not change membership.
- Repeating an allowed asset does not authorize any other identity.
- Reordering `excluded_assets` does not change exclusion precedence.
- Repeating an exclusion does not weaken it.
- Duplicating unrelated entries does not change another asset's decision.
- Case/whitespace-equivalent duplicates retain the existing normalization semantics.

This contract is separate from #343, which proves exclusions override an allowlist, and #369, which proves wildcard-looking or suffix-related text never expands durable asset authority.

## Safety boundary

These regressions are pure in-memory authorization evaluation. They perform no DNS resolution, socket/HTTP I/O, scanning, target interaction, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
