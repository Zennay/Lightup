# RED contract: blank durable asset identities

Issue: #376

This branch is an **acceptance contract, not a promotion candidate**. It is based on the active IP-asset canonicalization owner branch and intentionally contains no production-source change.

## Required fail-closed behavior

Before any durable authorization grant is persisted:

- whitespace-only allowlisted assets are rejected;
- a mixed allowlist containing a blank identity is rejected rather than silently filtered;
- blank excluded identities are rejected;
- non-string allowlisted identities are rejected;
- rejected scopes create no authorization-grant row.

The owning domain/asset-canonicalization composition may choose where to enforce the invariant, but the persisted grant boundary must satisfy it.

## Expected current state

The current owner source checks that `scope.assets` is a non-empty tuple but does not yet validate every contained identity. These tests are therefore expected to remain RED until #376 is absorbed by the source-owning chain.

## Safety

Authorization data-integrity only. No network I/O, target interaction, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
