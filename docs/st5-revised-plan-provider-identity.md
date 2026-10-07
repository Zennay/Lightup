# ST5 revised-plan provider identity integrity

## Scope

This acceptance slice is a tests/docs-only child of revised implementation-plan producer #503 at exact parent `6cc2d06096c60fc38fd63350206029c9703efdd6`.

It isolates provider identity provenance only. It does not modify #503, #524 provenance bounds, strict handoffs, scope authorization, or any target-capable path.

## Invariant

A model response used to create a revised implementation plan must originate from the exact built-in provider identity bound to `ModelRole.REMEDIATION_ADVISOR`.

## Ordinary substitution guard

A provider registered under the canonical provider ID but returning ordinary built-in string `forged-revision-provider` is already rejected by `ModelGateway.complete()` with `GatewayConfigurationError` before #503 receives the response.

## Expected RED: polymorphic identity

`ModelGateway.complete()` currently compares the returned provider ID to the binding by value. `ModelResponse` does not require an exact built-in string.

A crafted `str` subclass can therefore store `forged-revision-provider` while overriding equality/inequality to appear equal to `implementation-plan-revision-advisor`. The dedicated regression requires this case to receive the same gateway rejection as the ordinary mismatch.

The response keeps the exact requested model ID and role so the case isolates provider identity only.

## Safety

The regressions use only the in-memory model abstraction and existing deterministic fixture lineage. No external model or network call, target interaction, scanning, execution, remediation/retest action, deployment, security verdict, or attack-path mutation occurs.
