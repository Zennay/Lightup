# Shared gateway response-content runtime identity

Issue: #786  
Pinned parent: #574 exact head `3ae92d599832220598118b277383e3c667804287`

## Boundary

The gateway is the common provider boundary for remediation planning/review and
other model roles. #570/#572/#574 already make provider/model identities exact
and canonical. Response content still crosses that boundary without an exact
runtime-type check.

Canonical providers return built-in `str`. A provider-controlled `str`
subclass can override string methods that downstream remediation consumers use,
including `.strip()`.

## Acceptance contract

- exact built-in content remains accepted with provider/model/role unchanged;
- `ModelResponse.content` whose runtime type is a `str` subclass fails
  closed inside `ModelGateway.complete()`;
- rejection occurs before downstream remediation code can invoke subclass
  string behavior;
- no coercion/normalization is used to turn the subclass into an accepted
  built-in string.

The narrow source-owner repair is to require exact built-in response content
at the shared gateway boundary, alongside the existing exact provider/model
identity checks.

## Non-overlap

This branch is tests/docs only. #574 retains gateway production ownership. It
does not absorb provider/model identity work (#570/#572), configured identity
bounds (#574), persisted proposal content canonicality (#439), per-producer
output-size rules, scope authorization or target-capable behavior.

## Safety

The regression uses an in-memory provider only. No external model/network
request, target interaction, scanning, execution, remediation/retest execution,
deployment, verdict creation or attack-path mutation is added.
