# Immutable canonical ToolParameter schemas

Issue: #911

This acceptance contract is pinned directly above active ToolRegistry owner
PR #156 exact head `e84f2cd74d24f143c02b38cc05cb1c4c64352966`.

## Problem

`ToolDefinition` is frozen, but its annotated `parameters` tuple is not
runtime-enforced. A caller can construct an exact ToolDefinition with a
caller-owned mutable list. Registering that object stores the same definition,
so later mutation of the list changes the argument schema without another
registry admission step.

The same annotation-only boundary also permits ToolParameter subclasses or
duck-typed objects inside an otherwise exact definition.

## Required invariant

At registry admission:

- `parameters` is an exact built-in tuple;
- every tuple item is an exact `ToolParameter`;
- mutable/custom containers fail closed;
- parameter subclasses and duck objects fail closed;
- canonical exact tuple-backed schemas retain their required-argument behavior;
- rejection leaves registry contents unchanged.

This is separate from #907's outer ToolDefinition identity contract and #908's
exact boolean `required` field contract.

## Collision boundary

Tests/docs only. PR #156 remains the production source owner of ToolRegistry and
ToolDefinition validation.

No execution policy, domain/state, activation, worker, evidence-remediation,
remediation/retest execution, deployment, security-verdict or attack-path
source is changed.

## Safety

Offline schema-integrity validation only. No handler, network or target
interaction occurs.
