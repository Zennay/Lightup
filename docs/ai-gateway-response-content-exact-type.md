# Exact model-response content boundary

Issue: #786

## Purpose

The shared AI gateway is the provider trust boundary for evidence-remediation
consumers. Provider and model identifiers are already required to be canonical
built-in strings on the parent source owner. Response content needs the same
runtime-type guarantee before downstream remediation code can call string
methods such as `.strip()`, containment checks, or digest encoding.

## Acceptance invariant

`ModelGateway.complete()` must:

1. continue accepting ordinary exact built-in `str` content;
2. reject a `str` subclass before returning the provider response;
3. reject the polymorphic value without invoking subclass-defined string
   normalization behavior;
4. preserve provider/model routing semantics.

This is intentionally narrower than content-size, schema, remediation-policy,
or execution-authority validation.

## Expected RED

The parent #574 head validates exact `provider_id` and `model_id`, then
returns the provider response without checking `response.content`.

The focused regression therefore remains RED until the source owner adds an
exact built-in content-type guard at the shared gateway boundary.

## Collision boundary

This branch is tests/docs only above exact #574 head
`3ae92d599832220598118b277383e3c667804287`.

Production ownership of `src/lightup/ai/gateway.py` remains with #574. This
branch does not modify provider/model identity work or any remediation producer.

## Safety

In-process deterministic provider stubs only. No model network call, target
interaction, scanning, evidence collection, remediation/retest execution,
deployment, verdict creation, or attack-path mutation.
