# ToolParameter required boolean integrity

Issue: #908

This acceptance contract is pinned directly above active ToolRegistry owner
PR #156 exact head `e84f2cd74d24f143c02b38cc05cb1c4c64352966`.

## Problem

`ToolParameter.required` is annotated as a boolean but the runtime argument
validator consumes it through truthiness. A malformed falsy value such as
`0`, `""`, or `None` can therefore make a parameter optional without
crossing an explicit typed-tool schema decision.

That weakens the pre-handler typed argument boundary.

## Required invariant

At registry admission:

- every parameter's `required` field is an exact built-in `bool`;
- exact `True` keeps missing arguments fail-closed;
- exact `False` keeps intentionally optional parameters valid;
- non-boolean truthy/falsy values fail before registry insertion;
- malformed metadata is never normalized via Python truthiness;
- rejection leaves the registry unchanged.

## Collision boundary

This branch adds tests and documentation only. PR #156 retains all production
ownership of the ToolRegistry / ToolDefinition implementation.

The contract is separate from #907's outer `ToolDefinition` identity check
and from #156's capability-state, interaction and minimum-risk validation.

No execution-policy, domain/state, activation, target-capable worker,
evidence-remediation, remediation/retest execution, deployment,
security-verdict authority or attack-path source is modified.

## Safety

Offline metadata validation only. No handler, network or target interaction
occurs.
