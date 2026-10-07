# Shared gateway response-role binding

Issue: #795  
Pinned parent: #574 exact head `3ae92d599832220598118b277383e3c667804287`

## Boundary

The caller selects a `ModelRole` when it asks `ModelGateway.complete()` for a
completion. That requested role determines the configured provider/model
binding and is therefore part of the gateway's response provenance.

Python does not enforce the `ModelResponse.role: ModelRole` annotation at
runtime. The current gateway verifies provider/model identity and then returns
the provider response without binding the returned role to the request.

## Acceptance contract

- an exact canonical response using the exact requested `ModelRole` member
  remains accepted;
- a different `ModelRole` fails closed at the gateway;
- a plain built-in string with the same textual value as the requested role
  also fails closed;
- provider ID, model ID and content remain canonical in negative controls so
  the failure is isolated to role provenance.

The intended source-owner guard is an identity check at the provider return
boundary: `response.role is role`.

## Non-overlap

This branch is tests/docs only. #574 keeps shared gateway source ownership.
#570/#572 own provider/model response identity, #574 owns configured identity
bounds, #786 owns exact response-content type and #787 owns exact
`ModelResponse` object identity.

## Safety

All coverage uses an in-memory provider. No external model/network call,
target interaction, scanning, execution, remediation/retest execution,
deployment, security verdict or attack-path mutation is introduced.
