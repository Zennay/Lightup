# ST5 revised implementation-plan producer integrity pack

This branch composes five independent tests/docs-only acceptance slices directly above exact #503 head `6cc2d06096c60fc38fd63350206029c9703efdd6`.

## Included contracts

- exact response provider identity;
- exact response model identity;
- direct-construction lifecycle/action-authority integrity;
- direct revised-plan digest coherence;
- producer input/state atomicity and deterministic rejection.

## Composition boundary

The pack adds only the ten existing regression/contract files from the five component branches plus this manifest. It does not modify #503 production source or existing tests/docs, #501/#511 consumer source, the active shared-gateway repair stack, scope authorization, target-capable code, remediation/retest execution, deployment, verdicts or attack paths.

The component diffs are all pinned to the same exact #503 parent and contain no production-source changes. This pack is a combined validation surface only and does not take source or gateway ownership.

## Expected validation state

Producer atomicity is the green control. Provider/model exactness and direct authority/digest acceptance slices were created as expected-RED proofs against the pinned #503 parent; shared-gateway repairs may satisfy identity cases only after their own dependency stack lands and is reproven. Direct typed-artifact authority/digest contracts remain source-owner concerns.

Do not start duplicate CI merely to reproduce known RED cases, and do not promote this pack based on newer gateway branches without restacking/reproof.

## Safety

Planning-producer integrity tests and documentation only. Existing fixtures use in-memory providers. No external model/network call, target interaction, scanning, tool execution, remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
