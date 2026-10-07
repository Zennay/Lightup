# ST5 implementation-plan review-request integrity pack

This branch composes six independent tests/docs-only acceptance slices directly above the exact branch-only #280 handoff head `08dc953ed7fa9e38976be7d7f66a3ec381ae6124`.

## Included contracts

- strict parser caller-input purity;
- exact raw JSON input type;
- exact persisted mapping-object type;
- exact persisted scalar types;
- exact schema/rubric key and value types;
- exact persisted sequence-container type.

## Composition boundary

The pack adds only the twelve existing regression/contract files from the six component branches plus this manifest. It does not modify #280 production source or existing tests/docs, #278 builder source, #480 builder atomicity, #487 live-validation atomicity, #281/#283 review ownership, revision-request/revised-plan work, scope authorization, gateway behavior, target-capable code, remediation/retest execution, deployment, verdicts or attack paths.

All six component branches are pinned directly to the same exact #280 head. This pack is a combined validation surface only and does not take source ownership.

## Expected validation state

Parser input-purity is the green control. The five exact-type boundaries are expected-RED acceptance proofs until #280 absorbs their fail-closed type guards.

Do not start duplicate CI only to reproduce those known expected-RED cases, and do not treat this pack as promotion-ready while they remain unresolved.

## Safety

Persisted planning review-request integrity tests and documentation only. No model invocation, target interaction, scanning, tool execution, remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
