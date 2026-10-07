# ExecutionRequest object identity contract

Issue: #771  
Pinned parent: PR #163 exact head `3dfacdcf2d939cd5e19bf9ce143f03a0b16a4274`

## Boundary

`ExecutionPolicy.decide()` is an authorization boundary. Before reading request fields or selecting an interaction-specific path, it must establish that the caller supplied the canonical immutable request object:

```python
type(request) is ExecutionRequest
```

Structural compatibility is not sufficient.

## Acceptance matrix

- exact `ExecutionRequest` + ANALYSIS + ANALYSIS_ONLY: green control;
- duck-typed object exposing all expected fields: fail closed;
- `ExecutionRequest` subclass with canonical-looking values: fail closed.

The two non-canonical cases are intentionally expected RED on the pinned #163 source because `ExecutionPolicy.decide()` currently validates fields but not the outer request object.

## Why this is separate

This slice does not replace existing field-level contracts:

- #124 owns `InteractionKind` typing;
- #121 owns `requested_risk` typing;
- #162/#163 own the exact boolean lab marker;
- #567 owns request client/engagement identity;
- #575 owns request asset identity;
- #576 owns request capability identity;
- #740 owns the nested grant scope object;
- #741 owns the outer authorization-grant object.

The outer request identity check is the precondition that prevents caller-controlled object dispatch from reaching any of those narrower field checks.

## Collision boundary

This branch is tests/docs only. It does not modify `src/lightup/execution_policy.py` or any production source. PR #163 remains the source owner for the current execution-policy chain.

## Safety

Pure in-memory authorization narrowing acceptance. No DNS/network I/O, target interaction, scanning, handler execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
