# Shared gateway exact ModelResponse runtime contract

Issue: #787  
Pinned parent: #574 exact head `3ae92d599832220598118b277383e3c667804287`

## Boundary

`ModelProvider.complete()` promises a `ModelResponse`, and remediation
consumers rely on that bounded response shape. The shared gateway currently
reads response attributes directly without first proving the returned runtime
object is the canonical response type.

An arbitrary duck object or `ModelResponse` subclass can therefore carry
provider-defined attribute behavior across the shared boundary.

## Acceptance contract

- an exact `ModelResponse` with canonical provider/model/role/content remains
  accepted;
- an attribute-compatible non-`ModelResponse` object fails closed;
- a `ModelResponse` subclass fails closed;
- rejection happens before downstream field handling or remediation consumers.

The intended source-owner guard is exact runtime identity at the provider return
boundary: `type(response) is ModelResponse`.

## Non-overlap

This branch is tests/docs only. #574 keeps production gateway ownership.
#570/#572 retain provider/model response identity, #574 retains configured
identity bounds, and #786 separately owns exact built-in response-content
identity.

## Safety

All coverage uses an in-memory provider. No external model/network call,
target interaction, scanning, execution, remediation/retest execution,
deployment, verdict creation or attack-path mutation is introduced.
