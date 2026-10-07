# Direct ScopeDefinition risk identity contract

Issue: #773  
Pinned parent: PR #100 exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

## Boundary

An exact `AuthorizationGrant` carrying an exact `ScopeDefinition` is still not canonical if `ScopeDefinition.max_risk` is merely integer-compatible.

Before TARGET_ACTIVE policy compares requested risk with authorization scope risk, the grant scope must satisfy:

```python
isinstance(scope.max_risk, RiskLevel)
```

The value must be an actual `RiskLevel` member. Raw integers, booleans and foreign integer-enum members are not authorization state.

## Acceptance matrix

Green controls:

- canonical `RiskLevel.ELEVATED` permits an otherwise authorized ELEVATED request;
- canonical `RiskLevel.STANDARD` denies the same ELEVATED request.

Expected RED on the pinned #100 source:

- raw integer `99` must not behave as authority broader than every valid `RiskLevel`;
- raw integer `4` is still non-canonical even though it numerically matches ELEVATED;
- a foreign `IntEnum(99)` cannot inherit numeric comparison semantics to widen authority;
- boolean `True` must be rejected as a type error before integer comparison semantics are used.

The fail-closed reason is `authorization scope risk must be a RiskLevel`.

## Non-overlap

- #121 owns request risk typing plus durable grant issuance risk typing.
- #646 owns the outer scope object at issuance.
- #740 owns the outer direct `grant.scope` object at policy evaluation.
- #639 owns already-persisted scope revalidation.
- #575/#576 own runtime request asset/capability identities.
- #648 owns mutable collection snapshot semantics inside `ScopeDefinition`.

This issue owns only the **direct in-memory exact scope object's `max_risk` runtime identity**.

## Collision boundary

Tests/docs only. No production source is modified. PR #100 remains the relevant direct grant/source owner.

## Safety

Pure in-memory authorization narrowing acceptance. No DNS/network I/O, target interaction, scanning, handler execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
