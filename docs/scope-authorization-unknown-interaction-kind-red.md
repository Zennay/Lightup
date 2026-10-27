# Unknown interaction-kind admission — RED contract

## M7/ST5 scope-authorization boundary

`ExecutionPolicy.decide()` branches on three exact `InteractionKind` enum identities, then currently treats *everything else* as `TARGET_ACTIVE`. A future string or arbitrary object can therefore inherit the valid grant's active permission rather than being rejected for an unsupported interaction category.

## Required fail-closed behavior

- Admit only exact built-in `InteractionKind` members before evaluating grants.
- Reject unknown strings and arbitrary objects even if every active authorization field would otherwise allow the action.
- Preserve the existing authorized `InteractionKind.TARGET_ACTIVE` result and the existing ANALYSIS, PASSIVE_PUBLIC, LAB_ACTIVE behaviors.
- Never infer authority from a fallback branch or from a polymorphic `.value`.
- Do not add any target/network interaction to verification.

## Regression

`python -m unittest discover -s tests -p 'test_execution_policy_unknown_interaction_kind.py'`

The first two tests are intentionally RED against the current source. The canonical target-active control must stay GREEN. Production owner should fix in their existing `src/lightup/execution_policy.py` lane; this branch deliberately modifies only a new test module and this document.

No activation, grant store, executor, target handling, capability invocation, or deployment is modified.
