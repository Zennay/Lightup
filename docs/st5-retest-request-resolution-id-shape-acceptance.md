# ST5 retest-request canonical transition-resolution ID shape

Issue: #391

This is a tests/docs-only acceptance child of exact strict retest-request handoff
head `51ef9d8574e69c2f82c3f9635b508e835a822177`.

## Boundary

The upstream ST4 transition-resolution producer creates every resolution identity
as exactly:

`transition-resolution:<24 lowercase hex>`

The strict persisted retest-request handoff currently treats `resolution_id` as
only a generic canonical non-empty string. That admits persisted typed state with
a resolution identity shape the canonical ST4 producer cannot emit.

The regression keeps the rest of a real producer request intact, changes only
the persisted item `resolution_id`, and recomputes the exact matching public
`request_sha256`. A stale-digest failure therefore cannot satisfy this
contract.

## Required structural invariant

The persisted handoff must reject:

- a different prefix with an otherwise clean suffix;
- a `transition-resolution:` ID whose suffix is not exactly 24 characters;
- a suffix outside lowercase hexadecimal.

The canonical producer request must still round-trip.

This contract deliberately stops at structural shape. It does **not** attempt to
recompute the exact resolution identity because the run/evidence lineage needed
for that remains owned by the mandatory immediate live-lineage validator.

## Expected RED on current #359

Current #359 calls the generic canonical-string helper for `resolution_id`, so
all three forged shapes survive the identifier check. After recomputing a
matching request digest, the persisted parser reconstructs them as typed state.

## Collision boundary

This branch adds only:

- `tests/test_future_security_retest_request_resolution_id_shape_acceptance.py`;
- this document.

It does not modify #359 source/tests/docs, #387/#388/#389 files, #356/#357/#363,
retest authorization/tool-selection, scope authorization, or target-capable
code.

## Safety

Persistence-integrity only. No evidence collection, target interaction, tool
execution, remediation/retest execution, deployment, security verdict creation,
or attack-path mutation is introduced.
