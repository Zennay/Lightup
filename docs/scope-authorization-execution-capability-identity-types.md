# TARGET_ACTIVE execution capability identity type contract

This acceptance slice pins a narrow authorization-policy invariant above exact
#554 head `4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

## Why this matters

`ExecutionRequest.capability_id` is a Python type hint, not a runtime identity
guard. `ExecutionPolicy.decide()` delegates capability scope to
`ScopeDefinition.allows_capability()`, whose tuple-membership check is based on
Python equality.

A `str` subclass can retain a foreign underlying capability ID while
overriding equality so it compares equal to the canonical allowlisted
`network-services` identity. That lets a non-canonical capability object
inherit authority from a different capability identity.

## Required behavior

TARGET_ACTIVE policy evaluation must preserve all of these properties:

- the exact built-in allowlisted capability remains authorized when every other
  execution binding is canonical;
- an ordinary foreign built-in capability remains denied;
- an equality-spoofing `str` subclass carrying a foreign capability remains
  denied;
- a `str` subclass is denied even when its underlying text exactly matches the
  allowlisted capability;
- denial is deterministic across repeated evaluation;
- the immutable grant/scope is not mutated.

## Expected state

`tests/test_scope_authorization_execution_capability_identity_types.py`
contains two canonical controls and two polymorphic rejection cases.

Against the pinned #554 source:

- the exact allowlisted capability control is green;
- the ordinary foreign capability denial control is green;
- the foreign equality-spoofing subclass is expected RED because tuple
  membership can invoke its equality implementation;
- the matching-text subclass is expected RED because no exact built-in string
  guard exists.

The eventual repair is authorization narrowing only: validate a canonical
built-in capability identity before value equality participates in scope
membership.

## Collision boundary

Tests and documentation only. This branch does not modify
`src/lightup/execution_policy.py`, orchestration/ToolRegistry source,
`src/lightup/engagements.py`, domain persistence, or existing tests.

This is distinct from:

- #567 client/engagement execution-lineage identity typing;
- #575 runtime execution asset identity typing;
- #122 legacy Activation capability binding;
- durable asset/capability persistence work.

## Queue policy

Keep this expected-RED slice branch-only while existing scope-authorization work
occupies permanent self-hosted validation capacity.

## Safety

Pure in-memory authorization-policy narrowing proof. No state writes, model or
network calls, target interaction, scanning, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
