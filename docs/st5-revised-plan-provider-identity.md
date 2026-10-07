# ST5 revised-plan provider identity integrity

## Scope

This acceptance slice is a tests/docs-only child of revised implementation-plan producer #503 at exact parent `6cc2d06096c60fc38fd63350206029c9703efdd6`.

It isolates provider identity provenance only. It does not modify the #503 source owner, #524 provenance bounds, strict handoffs, scope authorization, or any target-capable path.

## Invariant

A model response used to create a revised implementation plan must originate from the exact provider bound to `ModelRole.REMEDIATION_ADVISOR`.

The producer already rejects a wrong role and wrong model identity. The provider identity must receive the same fail-closed treatment: a response may not substitute a different `provider_id` while preserving the bound model ID and role.

## Expected RED

The adversarial provider is registered under the canonical provider ID but returns a `ModelResponse` whose `provider_id` is `forged-revision-provider`. The response keeps the exact requested model ID and role.

At the #503 source head this response is accepted and the forged provider ID is incorporated into the revised-plan artifact and digest. The rejection test therefore remains intentionally RED until the #503 owner absorbs the provider-identity check.

## Safety

The regression uses only the in-memory model abstraction and existing deterministic fixture lineage. No external model or network call, target interaction, scanning, execution, remediation/retest action, deployment, security verdict, or attack-path mutation occurs.
