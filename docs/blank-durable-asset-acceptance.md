# RED contract: blank durable asset identities

Issue: #376

This branch is an **acceptance contract, not a promotion candidate**. It is based on the active IP-asset canonicalization owner branch and intentionally contains no production-source change.

## Required fail-closed behavior

Before any durable authorization grant is persisted:

- whitespace-only allowlisted assets are rejected;
- a mixed allowlist containing a blank identity is rejected rather than silently filtered;
- blank excluded identities are rejected;
- non-string allowlisted identities are rejected with a controlled validation error;
- non-string excluded identities are rejected before persistence;
- rejected scopes create no authorization-grant row.

The owning domain/asset-canonicalization composition may choose where to enforce the invariant, but the persisted grant boundary must satisfy it.

## Expected current state

The active IP-canonicalization owner source already rejects blank allowlisted strings. The remaining RED acceptance is concentrated on excluded-asset validation and controlled type rejection: `excluded_assets` currently has no equivalent per-entry validation, and a non-string allow entry fails only through incidental `.strip()` behavior. The source-owning chain should absorb only these remaining invariants.

## Safety

Authorization data-integrity only. No network I/O, target interaction, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
