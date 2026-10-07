# Scope authorization: canonical grant capability identities

Issue: #650  
Parent source owner: #554  
Exact parent head: `4c8d5651fc0e23f94514daae56b4e5fe0549de37`

## Boundary

`DomainStore.record_authorization_grant()` is the durable client-grant issuance boundary. It accepts the capability identities that are copied into both the returned `AuthorizationGrant.scope` and `authorization_grants.allowed_capabilities_json`.

The current validation assumes those identities are ordinary strings. It checks `.strip()`, compares a `set(...)` against the capability registry, and then indexes that registry with the original caller-owned values.

A `str` subclass can therefore keep one underlying text value while overriding hash/equality so registry validation observes another identity.

## Contract

Durable client-grant issuance must require every `allowed_capabilities` entry to be an exact built-in `str`.

Canonical planning capability IDs remain accepted unchanged.

A non-canonical capability input must fail before any grant row is written, including:

- a benign `str` subclass whose underlying value is an otherwise valid planning capability;
- a subclass storing a LAB_ONLY capability while hashing/comparing as a planning capability;
- a subclass storing an unknown capability while hashing/comparing as a planning capability.

The value admitted by registry validation and the value serialized into durable scope must therefore be the same canonical identity.

## Expected RED on #554

The exact #554 source currently performs the equivalent of:

```python
if any(not capability_id.strip() for capability_id in scope.allowed_capabilities):
    raise ValueError(...)
unknown = set(scope.allowed_capabilities).difference(known_capabilities)
...
if known_capabilities[capability_id].state is CapabilityState.LAB_ONLY:
    raise ValueError(...)
```

A crafted string subclass can store `ot-lab`, return `hash("web-baseline")`, and compare equal to `web-baseline`. The registry checks therefore treat it as the planning capability, while JSON serialization persists the underlying `ot-lab` text.

The same construction can persist an otherwise unknown capability under a spoofed planning-key comparison.

The intended repair is an issuance-time exact-string guard before any overridable string method, set membership, registry lookup, grant construction, or persistence.

## Collision boundary

This branch adds only:

- `tests/test_scope_authorization_grant_capability_input_types.py`
- this contract document.

There are **0 production/source changes**.

It is intentionally separate from:

- #576, runtime `ExecutionRequest.capability_id` typing;
- #639, execution-time validation of already-persisted nested scope entries;
- #376, durable allow/exclude asset-entry validation;
- #648, mutable `ScopeDefinition` collection aliasing;
- #100, ordinary known/LAB_ONLY capability-state restrictions;
- #554, durable execution-resolver source ownership.

## Safety

This proof uses a temporary SQLite database and in-memory domain objects only. It performs no DNS/network I/O, target interaction, scanning, exploit behavior, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.

Keep this acceptance branch source-free. The owning domain authorization chain should absorb the narrow exact-string guard and then re-prove the contract on its own exact head.
