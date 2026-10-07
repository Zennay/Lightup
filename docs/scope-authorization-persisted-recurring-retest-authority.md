# Scope authorization — persisted recurring-retest authority

Issue #888 pins the durable read boundary for
`authorization_grants.recurring_retest_allowed` above exact live-grant source
owner #107.

## Contract

The persisted representation is canonical only when SQLite returns exact integer
`0` or `1`.

- `0` reconstructs exactly `False`;
- `1` reconstructs exactly `True`;
- any other integer, text or BLOB value fails closed;
- rejection occurs before an `AuthorizationGrant` carrying recurring-retest
  authority is returned;
- failed reads do not normalize, repair or delete the stored value.

This is deliberately separate from #137, which owns write-time validation of
the caller-supplied `recurring_retest_allowed` argument.

## Why this matters

Using `bool(row["recurring_retest_allowed"])` treats every non-zero integer and
every non-empty text/BLOB value as `True`. Corrupt or legacy state must never
gain authority merely through Python truthiness.

## Expected state on the pinned parent

Pinned parent: exact PR #107 head
`c37ee27d922a7dd400eee1db39268f4a6269e431`.

Canonical false/true round trips are expected GREEN. Persisted values `2`,
`-1`, `"true"` and a non-empty BLOB are intentionally expected RED until
the durable reader validates the representation before boolean conversion.

## Safety and collision boundary

Tests and documentation only. No #107 production source is modified. #137
retains grant-issuance boolean typing ownership.

The regression uses temporary SQLite only and performs no DNS/network I/O,
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
