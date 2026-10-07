# ST5 implementation-plan revision-request exact check strings

## Scope

This acceptance slice is a tests/docs-only child of the bounded implementation-plan revision-request producer in #284.

- exact parent head: `c5fcb1d0d5f91d861010a1e06e6a764e2e917326`
- acceptance issue: #530
- source owner: #284

It is separate from #528/#529, which owns the outer direct metadata/container exactness contract. It does not modify #284 source, #486 builder atomicity, #501/#506 persisted parser work, #510/#516/#522 type slices, #507 live validation, or scope authorization.

## Invariant

Every entry in the typed `required_revisions` tuple must be an exact built-in `str` naming a canonical implementation-plan review check.

A string subclass is not accepted even when its stored text equals a canonical rubric value.

## Expected RED at #284

The current validator uses `isinstance(item, str)`. A `str` subclass containing a valid rubric value therefore passes non-empty checks, uniqueness, rubric membership, ordering and digest construction.

The regression expects the canonical exact-string control to remain green and the subclass rejection test to fail because no `ValueError` is raised.

## Required source-owner repair

The #284 owner should require `type(item) is str` for every `required_revisions` entry before uniqueness/order/digest validation. Reject rather than normalize.

## Safety

Pure in-memory planning-metadata integrity proof only. No model invocation, target interaction, scanning, tool/remediation/retest execution, deployment, verdict creation, or attack-path mutation.
