# Scope authorization: exact risk self-approval identity

Issue: #657

## Boundary

`DomainStore.decide_risk_elevation()` prevents self-approval by comparing the
persisted `requested_by` identity with `AccessContext.user_id`.

That comparison is authorization-significant. A context identity that is not an exact
built-in string can override equality while carrying the same underlying identity text,
so value-comparison alone is not a canonical identity boundary.

## Required contract

- canonical same-operator identity remains denied;
- a `str` subclass carrying the same identity cannot make equality report false and
  bypass the self-approval guard;
- denial leaves status `PENDING`, `decided_by=None`, and `decided_at=None`;
- an unrelated canonical operator remains able to decide the request.

The narrow repair may live at the decision boundary or at shared `AccessContext`
construction, but it must make actor identity exact before authorization-significant
comparison.

## Collision boundary

This branch is tests/docs only and is pinned above exact #554 head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

It does not modify #135/#146 decision source, #656 justification intake, grant/resolver
identity work, engagement lifecycle logic, or target-capable behavior. Source-owner
guidance belongs on #146.

## Safety

Authorization identity narrowing only. No target interaction, network activity,
scanning, model/tool execution, remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
