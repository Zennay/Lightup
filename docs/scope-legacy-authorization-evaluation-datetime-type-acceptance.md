# Legacy authorization evaluation datetime type acceptance

Tracks #733 as a collision-free acceptance contract above the active legacy authorization source owner PR #100.

## Pinned source owner

- Parent PR: #100
- Parent head: `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`
- Branch: `chatgpt/scope-authorization-legacy-evaluation-datetime-type-red-20261007`
- Production source changes in this branch: **0**

## Threat

`Authorization.is_current(now=...)` compares the caller-supplied evaluation instant on the left side of the validity-window comparisons:

- `now < valid_from`
- `now > valid_until`

A `datetime` subclass can override `__lt__` and `__gt__` and suppress both comparisons. On the pinned parent, that can make a future or expired authorization report itself as current.

## Required contract

An explicit evaluation instant must be either omitted or an exact built-in, timezone-aware `datetime`. Subclasses are rejected before any validity comparison. Exact built-in datetimes retain the inclusive boundary behavior already established by #295.

## Expected state on the pinned parent

The canonical exact-`datetime` control is green.

The two polymorphic evaluation-time tests are intentionally **RED** until PR #100 absorbs the exact-type guard:

1. a spoofing evaluation datetime cannot bypass a future `valid_from`;
2. a spoofing evaluation datetime cannot bypass an expired `valid_until`.

## Collision boundary

This branch adds only this document and its dedicated regression module. It does not modify `src/lightup/models.py` or any source owned by #100, #403, #731, scope policy, activation/capability, durable grants/sessions, execution policy, target-capable workers, evidence-remediation, deployment, verdict or attack-path lanes.

## Safety

Offline/in-memory authorization narrowing only. No DNS/network I/O, target interaction, scanning, exploit behavior, execution widening, remediation/retest execution, deployment, verdict creation or attack-path mutation.
