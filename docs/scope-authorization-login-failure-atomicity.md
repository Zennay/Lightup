# Concurrent login failure accounting atomicity

Issue: #910

Pinned source owner: draft PR #670 exact head
`68318a318d828815bc50002114f64037ed06387e`.

## Problem

`DomainStore.authenticate()` currently:

1. reads the durable failure row;
2. closes that read connection;
3. performs password verification;
4. opens a new connection and writes the next failure count.

Two failed authentications can therefore read the same old count and both
persist the same incremented value. One failure is lost and brute-force lockout
is delayed.

## Required invariant

- failure-state read/check/update for one canonical email is serialized;
- two concurrent failures from an empty counter produce durable
  `failures == 2`;
- no successful user/session state is created;
- ordinary single-thread failure and lockout behavior is unchanged;
- an implementation may satisfy the contract with a serialized transaction or
  an equivalent atomic database update.

## Regression design

The acceptance test replaces password verification with a deterministic local
failure stub.

The first authentication is paused only after it reaches verification. The
second authentication is then started.

On current source, both failure-state reads have already observed the same
empty row, so both later write `1`.

A future implementation that obtains a write/serialization lock before the
state read may block the second path instead. The test releases the first path
after a bounded observation window, allowing that serialized implementation to
complete and persist `2` without deadlock.

## Collision boundary

Tests/docs only. PR #670 retains `src/lightup/domain.py` production ownership.

#903 and #906 cover durable lockout timestamp/counter canonicality. This issue
owns only concurrent failure-accounting serialization.

No session token/TTL/CSRF, password-text, grant, execution-policy, activation,
target-capable, evidence-remediation, deployment, verdict or attack-path source
is changed.

## Safety

Temporary SQLite and deterministic local authentication failure only. No real
password hashing, network target interaction, scanning, capability execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation.
