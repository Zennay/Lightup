# ST5 revised-plan exact model identity

## Scope

This acceptance slice is a tests/docs-only child of revised implementation-plan producer #503 at exact parent `6cc2d06096c60fc38fd63350206029c9703efdd6`.

It owns only exact response model identity at the producer boundary. #524 retains provenance length/NUL bounds, #555/#556 retain provider-ID substitution coverage, #557/#558 retain direct authority state, #559/#561 retain direct digest coherence, and #511 children retain persisted-parser typing.

## Invariant

The revised-plan producer must accept only an exact built-in model ID equal to the model configured for `ModelRole.REMEDIATION_ADVISOR`.

A response must fail closed if its `model_id` is a polymorphic string object whose underlying value differs from the configured model even when overridden equality/inequality methods claim a match.

## Expected RED

At #503 head the producer performs a value comparison:

`response.model_id != binding.model_id`

`ModelResponse` has no exact-type guard. The adversarial `str` subclass stores `forged-revision-model` while reporting equality with `implementation-plan-revision-v1`. The current producer therefore accepts it and records forged provenance instead of raising the existing wrong-model error.

## Safety

The regression uses only the in-memory recording provider and deterministic planning fixtures. No external model/network call, target interaction, scanning, tool/remediation/retest execution, deployment, verdict creation, or attack-path mutation occurs.
