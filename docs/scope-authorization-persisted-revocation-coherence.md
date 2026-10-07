# Persisted revocation coherence contract

This acceptance slice pins one execution-time invariant for durable authorization
grants above the exact `#554` resolver head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

## Durable state invariant

Revocation is one atomic authorization fact with three persisted fields:

| State | `revoked_at` | `revoked_by` | `revocation_reason` | Execution |
| --- | --- | --- | --- | --- |
| canonical unrevoked | NULL | NULL | NULL | may remain eligible |
| canonical revoked | aware timestamp | non-blank actor | non-blank reason | denied |
| partial/corrupt | NULL | populated or NULL | populated or NULL | denied |

A durable row with no revocation timestamp but at least one populated revocation provenance field is
not canonical unrevoked state. The execution resolver must fail closed rather
than let `AuthorizationGrant.is_current()` reinterpret that row as active.

## Acceptance proof

`tests/test_scope_authorization_persisted_revocation_coherence.py` provides:

- a canonical unrevoked green control;
- a canonical revoked green control;
- expected rejection when actor + reason remain without `revoked_at`;
- expected rejection when only actor remains without `revoked_at`;
- expected rejection when only reason remains without `revoked_at`;
- durable-state snapshots proving rejection never repairs or normalizes the row.

Against the pinned `#554` source, the three partial-state cases are expected
RED: the resolver reconstructs the row with `revoked_at=None`, and
`is_current()` therefore treats it as unrevoked.

## Ownership boundary

This branch is tests/documentation only. It deliberately does not edit
`src/lightup/domain.py`; draft `#554` remains the source owner for
`DomainStore.resolve_authorization_for_execution`.

This contract is separate from:

- `#471`: persisted time, approval/reference provenance, and scope-schema integrity;
- `#551`: persisted engagement lifecycle integrity;
- `#552`: durable engagement/client ownership;
- `#138`: recurring-retest boolean integrity;
- `#100`: core grant revocation operations.

The narrow source-owner repair is to reject incoherent persisted revocation
tuples before reconstructing or returning execution authority.

## Safety

This is authorization narrowing only. The tests mutate a temporary SQLite row
and call the execution resolver in-process. They perform no DNS or network I/O,
target interaction, scanning, exploit behavior, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
