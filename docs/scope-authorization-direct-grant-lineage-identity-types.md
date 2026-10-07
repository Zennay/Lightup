# Direct AuthorizationGrant lineage identity integrity

Issue: #743

## Purpose

The standalone TARGET_ACTIVE policy boundary must not accept non-canonical runtime
identity objects from an otherwise exact `AuthorizationGrant`.

`ExecutionRequest.client_id` and `engagement_id` are request-side lineage.
Issue #567 already owns their exact-type acceptance. This contract covers the
opposite side of the comparison: the lineage stored on the direct grant object.

## Required contract

For TARGET_ACTIVE evaluation:

- `AuthorizationGrant.client_id` is an exact built-in, non-empty `str`;
- `AuthorizationGrant.engagement_id` is an exact built-in, non-empty `str`;
- foreign string subclasses cannot override equality/inequality to impersonate
  canonical request lineage;
- same-text string subclasses are still non-canonical and must fail closed;
- exact built-in matching identities keep the existing allow path;
- exact built-in mismatches keep the existing deny reasons;
- rejection is pure and does not rewrite the request, grant, or scope.

## Expected acceptance partition on PR #100

Pinned source owner:

`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

Current `ExecutionPolicy.decide()` compares the grant fields by value only:

```python
if grant.client_id != request.client_id:
    ...
if grant.engagement_id != request.engagement_id:
    ...
```

Therefore the dedicated regression has three green controls:

1. exact matching lineage remains allowed;
2. exact foreign client lineage remains denied;
3. exact foreign engagement lineage remains denied.

Four cases are expected RED until the source owner absorbs an exact-type guard:

1. foreign grant client identity with equality spoofing;
2. foreign grant engagement identity with equality spoofing;
3. same-text grant client `str` subclass;
4. same-text grant engagement `str` subclass.

## Non-overlap

- #567: request-side client/engagement identity types;
- #741: outer direct authorization-grant object type;
- #740: nested direct grant scope object type;
- #552/#554: durable persisted lineage re-resolution;
- #649: issuance-time approval/reference provenance;
- #100 remains the production source owner.

This slice changes tests/docs only. It does not modify execution policy,
engagement/domain source, activation, orchestration, target-capable handlers,
evidence-remediation, deployment, verdict, or attack-path state.

## Safety

Pure in-memory authorization narrowing. No DNS/network I/O, target interaction,
scanning, capability execution, remediation/retest execution, deployment, or
authority widening.
