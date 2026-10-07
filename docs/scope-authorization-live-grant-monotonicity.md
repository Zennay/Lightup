# Monotonic live authorization revalidation

Issue: #951  
Production owner: draft PR #107  
Pinned owner head: `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

A `RunContext` carries the authorization snapshot that existed when the run was created. PR #107 correctly re-resolves that grant before every TARGET_ACTIVE dispatch so revocation and narrowing can take effect.

The live grant must not become an implicit privilege-escalation channel for an already-created run. Revalidation is therefore monotonic: live state may remove authority, but it may not add authority that the run snapshot never held.

## Acceptance contract

For the same grant id and lineage:

- a live grant may narrow `assets`, `allowed_capabilities`, or `max_risk`;
- canonical execution inside the intersection of snapshot and live authority remains allowed;
- live state may not add an asset absent from the run snapshot;
- live state may not remove an asset exclusion that constrained the run snapshot;
- live state may not add a capability absent from the run snapshot;
- live state may not raise `max_risk` above the run snapshot grant;
- any broadening fails before handler dispatch and evidence persistence;
- neither the snapshot nor live grant is rewritten or normalized.

This is distinct from persisted-row safety/schema validation (#139/#479) and resolver-output object identity (#949). PR #107 remains the production owner.

## Safety

All regressions use exact in-memory grants, temporary SQLite and inert handlers. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
