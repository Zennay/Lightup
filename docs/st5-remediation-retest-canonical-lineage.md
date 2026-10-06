# ST5 remediation/retest canonical lineage acceptance

Issue #381 covers a persisted-boundary invariant that is stricter than simple
non-emptiness.

## Upstream contract

ST4 transition resolutions already require lineage identifiers to be canonical:
they cannot have leading/trailing whitespace, control characters, or length
above 256 characters. Their evidence, capability, effect, and current-path
tuples are also sorted and unique.

The ST5 persisted remediation/retest handoff must not admit a state that the
upstream producer cannot emit merely because the caller recomputed the public
plan digest.

## Acceptance

The dedicated regression starts from real producer plans and recomputes an exact
matching `plan_sha256` after each mutation. It requires fail-closed rejection
for:

- nonblank identifiers with leading/trailing whitespace;
- embedded control characters;
- identifiers longer than 256 characters;
- noncanonical lineage-list elements;
- unique but unsorted lineage lists.

Canonical producer payloads continue to round-trip.

## Distinction from #377

Issue #377 covers identifiers whose `.strip()` is empty. This contract does
not rely on blank strings: every whitespace-form case remains non-empty after
trimming, and it additionally covers control characters, maximum identifier
length, and canonical collection ordering.

## Parallel boundary

This is tests/docs only on exact PR #190 head
`c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`. It does not modify the active
handoff source or any existing #375/#377/#378 integrity file.

## Safety

Persistence-integrity only. No evidence collection, model invocation, target
interaction, tool execution, remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
