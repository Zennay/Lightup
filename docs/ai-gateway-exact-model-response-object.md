# Exact ModelResponse provider boundary

Issue: #787

## Purpose

`ModelProvider.complete()` is annotated to return `ModelResponse`, but provider
code is an external implementation boundary. The shared gateway must establish
the exact canonical response object before reading provider-controlled fields
that evidence-remediation consumers later trust.

## Acceptance invariant

`ModelGateway.complete()` must:

- continue accepting an exact `ModelResponse`;
- reject an attribute-compatible duck object;
- reject a `ModelResponse` subclass;
- establish the exact response-object boundary before downstream field
  validation and before returning anything to remediation consumers.

## Expected RED

At exact #574 head
`3ae92d599832220598118b277383e3c667804287`, the gateway reads
`response.provider_id` and `response.model_id` immediately after provider
completion. No exact outer-object check exists, so both adversarial cases are
currently producer-admissible.

## Collision boundary

Tests/docs only. #574 retains all production ownership of
`src/lightup/ai/gateway.py`.

This is separate from #786, which concerns the runtime type of
`ModelResponse.content` after the response object itself has been established.

## Safety

Deterministic in-memory provider stubs only. No external model/network call,
target interaction, scanning, remediation/retest execution, deployment,
verdict creation, or attack-path mutation.
