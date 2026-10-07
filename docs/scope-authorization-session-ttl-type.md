# Canonical session TTL authorization contract

Tracked by GitHub issue #803.

## Boundary

`DomainStore.create_session(user_id, ttl_seconds)` mints durable authenticated
session state. The session expiry therefore participates directly in the
authorization lifetime of the resulting credential.

The canonical input contract is:

- `ttl_seconds` is an **exact built-in `int`**;
- the value is between 60 seconds and 30 days, inclusive;
- numeric equivalence is not a substitute for canonical runtime identity.

Floats, `int` subclasses, integer enums and other numeric duck types are not
canonical session-lifetime inputs even when they compare equal to a valid
integer TTL.

## Why this is fail-closed

The pre-existing range comparison accepts values by numeric behavior. For
example, `60.0`, an `int` subclass containing `60`, and an `IntEnum`
member with value `60` all satisfy the numeric range check and can reach
`timedelta(seconds=...)`.

That is broader than the declared persistence contract and allows caller-owned
numeric behavior to cross an authentication boundary. Session lifetime should
be produced from one unambiguous primitive type before any session row exists.

## Required behavior

Canonical exact integers at both inclusive bounds remain accepted. Exact
integers outside the range remain rejected.

Every non-canonical numeric representation is rejected before session
persistence. Rejection creates no new session row and does not mutate user or
existing-session state.

## Ownership and non-overlap

This acceptance slice is pinned to PR #670 exact head
`68318a318d828815bc50002114f64037ed06387e`.

PR #670 retains all `src/lightup/domain.py` production-source ownership. This
slice adds only tests and documentation. Session token identity (#705), durable
session temporal reconstruction (#706), durable CSRF identity (#708), and the
session integrity composition (#710) remain separate owners.

## Safety

The regression uses only generated local session material and temporary
SQLite. It performs no DNS/network I/O, target interaction, scanning, model or
tool execution, remediation/retest execution, deployment, verdict creation, or
attack-path mutation.
