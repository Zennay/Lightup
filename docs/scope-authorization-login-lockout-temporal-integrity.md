# Durable login lockout temporal integrity

Issue: #903

Pinned source owner: draft PR #670 exact head
`68318a318d828815bc50002114f64037ed06387e`.

## Problem

`DomainStore.authenticate()` trusts the persisted
`login_failures.locked_until` value as parseable, timezone-aware ISO datetime
text.

A malformed value currently leaks `ValueError`. A timezone-naive value parses,
then leaks a naive/aware comparison error against the UTC authentication clock.

Authentication lockout is an authorization boundary. Corrupt durable lockout
state must deny authentication deterministically rather than fall through
incidental parser/runtime behavior.

## Required invariant

- canonical aware future lockout timestamps remain locked;
- canonical aware expired timestamps preserve the normal authentication path;
- malformed or timezone-naive persisted lockout timestamps fail closed through
  controlled `AccountLockedError`;
- rejection happens before password verification can authenticate the account;
- corrupt rows are not deleted, normalized or rewritten during rejection;
- no malformed lockout state can silently weaken sign-in protection.

## Collision boundary

This branch adds one regression module and this contract document only.

It does not modify:

- `src/lightup/domain.py` (owned by PR #670 and adjacent domain owners);
- session-token identity #705;
- session temporal integrity #706;
- CSRF integrity #708;
- session TTL typing #803;
- password-text intake #806;
- durable grant, risk, activation or execution-policy source;
- target-capable workers, evidence-remediation, deployment, verdict or
  attack-path state.

The branch is intentionally expected RED until the active domain source owner
absorbs the narrow persisted-lockout decoder guard.

## Safety

Temporary SQLite and local credential state only. No DNS/network I/O, target
interaction, scanning, capability execution, remediation/retest execution,
deployment, verdict creation or attack-path mutation.
