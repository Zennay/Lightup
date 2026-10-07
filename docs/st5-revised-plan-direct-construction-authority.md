# ST5 revised-plan direct-construction authority integrity

## Scope

This acceptance slice is a tests/docs-only child of revised implementation-plan producer #503 at exact parent `6cc2d06096c60fc38fd63350206029c9703efdd6`.

It owns only the typed artifact's direct-construction safety stop line. It does not modify #503 source, #524 provenance bounds, #511 persisted handoff/parser behavior, revised-plan review requests, scope authorization, or target-capable code.

## Invariant

`FutureRemediationImplementationPlanRevisionProposal` is planning text only. Its typed constructor must enforce the same non-executable state that the producer emits and the later persisted handoff validates.

Direct construction or `dataclasses.replace()` must fail closed if caller code attempts to:
- claim `implementation_plan_accepted=True`;
- set any code/tool/execution/target/retest/deploy/attack-path authority flag;
- clear the revised-plan-created lifecycle marker;
- resolve future semantics;
- create a security verdict.

## Expected RED

At #503 head the frozen dataclass has no `__post_init__` validation. Replacing the canonical producer result with `implementation_plan_accepted=True, execution_allowed=True` succeeds, as does replacing unresolved/not-evaluated state with resolved/secure values.

The acceptance tests intentionally expect construction-time rejection, so they remain RED until the #503 source owner adds typed-artifact validation.

## Safety

Only deterministic in-memory planning fixtures are used. No external model/network call, target interaction, scanning, tool/remediation/retest execution, deployment, verdict creation, or attack-path mutation occurs.
