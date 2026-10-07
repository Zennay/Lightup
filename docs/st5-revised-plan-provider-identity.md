# ST5 revised-plan provider identity integrity

## Scope

This acceptance slice is a tests/docs-only child of revised implementation-plan producer #503 at exact parent `6cc2d06096c60fc38fd63350206029c9703efdd6`.

It isolates provider identity provenance only. It does not modify the #503 source owner, #524 provenance bounds, strict handoffs, scope authorization, or any target-capable path.

## Invariant

A model response used to create a revised implementation plan must originate from the exact provider bound to `ModelRole.REMEDIATION_ADVISOR`.

The producer already rejects a wrong role and wrong model identity. The gateway also enforces provider identity before the producer receives the response.

## Proven guard

The adversarial provider is registered under the canonical provider ID but returns a `ModelResponse` whose `provider_id` is `forged-revision-provider`. The response keeps the exact requested model ID and role.

`ModelGateway.complete()` rejects that response with `GatewayConfigurationError` before #503 can construct or digest a revised-plan artifact. The paired canonical control proves that the legitimate bound provider continues to produce the same non-executable revised plan.

This closes the suspected provider-substitution gap at the shared gateway layer; no #503 source change is required.

## Safety

The regression uses only the in-memory model abstraction and existing deterministic fixture lineage. No external model or network call, target interaction, scanning, execution, remediation/retest action, deployment, security verdict, or attack-path mutation occurs.
