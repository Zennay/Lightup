# Canonical ToolDefinition registry boundary

Issue: #907

This acceptance contract is pinned directly above active ToolRegistry owner
PR #156 exact head `e84f2cd74d24f143c02b38cc05cb1c4c64352966`.

## Problem

PR #156 correctly validates important fields on a tool definition before
registry insertion, including interaction kind, minimum risk and capability
state.

The registry still trusts the outer object by annotation only. A
`ToolDefinition` subclass or duck-typed object can therefore carry
canonical-looking fields while replacing methods such as
`validate_arguments()`. The executor later calls that stored method before
policy/handler dispatch, so polymorphic definition behavior can replace the
typed argument contract.

## Required invariant

At `ToolRegistry.register()`:

- only `type(definition) is ToolDefinition` is accepted;
- canonical exact definitions keep existing behavior;
- `ToolDefinition` subclasses fail before insertion;
- structurally compatible duck definitions fail before insertion;
- rejected objects cannot contribute overridden argument-validation behavior;
- rejection leaves registry contents unchanged.

This exact-object contract complements, rather than replaces, #156's
capability-state / interaction / minimum-risk checks.

## Collision boundary

This branch changes tests and documentation only. PR #156 remains the sole
production-source owner for the relevant `src/lightup/ai/orchestration.py`
ToolRegistry code.

It does not modify execution policy, domain/state, activation, worker handlers,
evidence-remediation, remediation/retest execution, deployment,
security-verdict authority or attack-path state.

## Safety

Offline registry-integrity validation only. No handler, network or target
interaction occurs.
