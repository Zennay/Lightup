# Scope authorization: canonical risk-elevation justification

Issue: #656

## Boundary

`DomainStore.request_risk_elevation()` persists a human justification as part of the
authorization-elevation audit trail.

The current implementation validates one `.strip()` result and later persists the
result of a second `.strip()` call. A polymorphic or duck-typed input can therefore
present different values to validation and persistence.

## Required contract

The intake boundary must:

1. require `type(justification) is str`;
2. derive one local canonical snapshot with `justification.strip()`;
3. reject an empty canonical snapshot before writing any `risk_approvals` row;
4. use that same snapshot for the returned record and durable row;
5. keep ordinary built-in string behavior unchanged.

A stateful `str` subclass and a non-string object exposing `.strip()` are rejection
controls. A normal padded built-in string is the green control and remains trimmed.

## Collision boundary

This acceptance branch is tests/docs only and is pinned above exact #554 head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

It does not modify the active domain implementation. The eventual repair belongs with
risk-elevation intake owner #132. It is separate from risk enum/destructive-risk intake,
decision validation/serialization, grant provenance, execution-time grant reconstruction,
engagement lifecycle work, and target-capable behavior.

## Safety

This contract only narrows authorization audit integrity. It adds no target interaction,
network activity, scanning, model/tool execution, remediation/retest execution,
deployment, verdict creation, or attack-path mutation.
