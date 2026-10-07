# Durable login failure counter integrity

Issue: #906

Pinned source owner: draft PR #670 exact head
`68318a318d828815bc50002114f64037ed06387e`.

## Problem

`DomainStore.authenticate()` trusts the persisted
`login_failures.failures` value.

When `locked_until` is absent, a correct password currently deletes the row
without validating the counter. A corrupted negative or at/above-threshold
counter can therefore be silently cleared. On failed authentication the code
also performs arithmetic directly on the stored value, making behavior depend
on SQLite's runtime storage type.

The durable failure counter is part of brute-force authorization state and must
have one canonical domain before credentials are evaluated.

## Required invariant

For an unlocked row:

- `failures` is a SQLite integer;
- `0 <= failures < LOGIN_MAX_FAILURES`;
- negative, at/above-threshold, REAL and TEXT values fail closed;
- corrupted state is denied through controlled `AccountLockedError` before
  password verification;
- rejection does not delete, reset, normalize or rewrite the row.

Canonical in-range state preserves the existing behavior, including successful
login clearing the failure counter.

A locked row remains separately governed by #903's canonical
`locked_until` contract and the producer invariant that locking resets the
counter to zero.

## Collision boundary

This branch adds one regression module and this document only. It does not
modify `src/lightup/domain.py`, which remains owned by PR #670 and adjacent
domain source branches.

It does not overlap session token/TTL/CSRF contracts, password-text #806,
grants, execution policy, activation, target-capable workers,
evidence-remediation, deployment, verdict or attack-path state.

## Safety

Temporary SQLite and local authentication state only. No DNS/network I/O,
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
