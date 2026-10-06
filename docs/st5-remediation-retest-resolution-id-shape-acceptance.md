# ST5 remediation/retest canonical transition-resolution ID shape

Issue: #396

This tests/docs-only acceptance child starts from exact strict
remediation/retest-plan handoff #190 head
`c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`.

## Boundary

The upstream ST4 transition-resolution producer emits each resolution identity
as exactly:

`transition-resolution:<24 lowercase hex>`

The persisted remediation/retest-plan handoff currently treats
`resolution_id` as only a non-empty string. A caller can therefore persist a
clean but impossible resolution identity and recompute a matching
`plan_sha256`.

The regression changes only the persisted item `resolution_id`, recomputes the
exact public plan digest, and requires rejection independently of stale-digest
protection.

## Required structural invariant

The persisted handoff must reject:

- a different prefix with an otherwise clean suffix;
- a `transition-resolution:` suffix that is not exactly 24 characters;
- suffix characters outside lowercase hexadecimal.

Canonical producer output must continue to round-trip.

Exact resolution-ID recomputation deliberately remains outside this parser
contract because proposal/run/evidence lineage belongs to the mandatory live
validator.

## Expected RED on exact #190

The current parser calls the generic non-empty-string helper for
`resolution_id`, so all three forged shapes survive parsing. With a recomputed
matching `plan_sha256`, typed persisted state is reconstructed even though the
canonical ST4 producer cannot emit it.

## Collision boundary

This branch adds only:

- `tests/test_future_security_remediation_retest_resolution_id_shape_acceptance.py`;
- this document.

It is distinct from #381, #383, #384, #385, #386 and downstream #391, and does
not modify #190 source/tests/docs or active sibling files.

## Safety

Persistence-integrity only. No evidence collection, model invocation, target
interaction, tool/remediation/retest execution, deployment, verdict creation or
attack-path mutation is introduced.
