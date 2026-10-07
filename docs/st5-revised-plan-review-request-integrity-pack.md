# ST5 revised implementation-plan review-request integrity pack

This branch composes three independent tests/docs-only acceptance slices directly above the exact #517 head `f8de987ad069a784751a9e38ce258f6a118cea11`.

## Included contracts

- #527 exact fixed metadata/container types for the revised-plan review-request artifact;
- #533 exact built-in strings inside the fixed `required_checks` rubric;
- #549 deterministic detached snapshot isolation.

## Composition boundary

The pack adds only the six existing regression/contract files from #527, #533 and #549 plus this manifest. It does not modify #517 production source or existing tests/docs, #519 persisted review-request handoff ownership, #525 builder atomicity, #511 revised-plan handoff, scope authorization, gateway behavior, target-capable code, remediation/retest execution, deployment, verdicts or attack paths.

All three component branches are pinned to the same exact #517 parent. This pack is a combined acceptance surface only and does not take source ownership.

## Expected validation state

The metadata-subclass and review-check string-subclass cases are expected RED until #517 absorbs exact-type guards. Snapshot isolation is the green control.

Do not start duplicate CI only to reproduce the known expected-RED cases, and do not treat this pack as promotion-ready while they remain unresolved.

## Safety

Planning-metadata integrity tests and documentation only. No model invocation, target interaction, scanning, tool execution, remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
