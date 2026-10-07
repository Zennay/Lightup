# Live authorization validity-window monotonicity

Issue: #953  
Production owner: draft PR #107  
Pinned owner head: `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

A run carries an immutable authorization snapshot with a bounded validity window. PR #107 re-resolves the same grant before TARGET_ACTIVE dispatch so revoked or narrowed live state can stop a stale run.

Revalidation must not silently extend the time authority of that existing run. A same-id live grant with an earlier start or later expiry would give the run authority during time that its snapshot never authorized.

## Acceptance contract

For the same grant id and lineage:

- a live validity window contained inside the snapshot window remains allowed;
- live `valid_from` must be greater than or equal to snapshot `valid_from`;
- live `valid_until` must be less than or equal to snapshot `valid_until`;
- an expired snapshot cannot be revived by extending the live expiry;
- a future snapshot cannot be activated early by moving the live start backward;
- temporal broadening fails before handler dispatch and evidence persistence;
- neither grant object is rewritten or normalized.

This is separate from #951, which owns asset/exclusion/capability/risk monotonicity, and from exact datetime-type contracts such as #647/#738. PR #107 retains production ownership.

## Safety

All regressions use exact timezone-aware in-memory grants, temporary SQLite and an inert handler. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
