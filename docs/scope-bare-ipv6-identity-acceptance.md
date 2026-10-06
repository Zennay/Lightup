# Scope authorization: bare IPv6 identity acceptance

Issue: #291

This tests/docs-only contract is based on exact current `main`
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

## Boundary

A bare canonical IPv6 literal must never be exposed to authorization logic as a
truncated host token.

The current schemeless `urlparse` path turns:

`2606:4700:4700::1111`

into normalized host `2606`.

That is more than a diagnostic inconsistency: if `explicit_hosts` contains
`2606`, the bare IPv6 target can be treated as that unrelated explicit host
and receive public scope with a current authorization.

The acceptance therefore permits only two safe outcomes for bare IPv6:

- recognize the full IPv6 identity and apply normal explicit-network policy; or
- reject it explicitly as an invalid target with no normalized host identity.

It additionally proves that the truncated prefix cannot mint explicit-host
scope. Bracketed IPv6 authority remains a green positive control.

## Expected RED on current main

- bare IPv6 exposes normalized host `2606`;
- an explicit host policy for `2606` can authorize the bare IPv6 target.

## Collision boundary

Only one regression module and this document are added. No
`src/lightup/scope.py`, #290/#292/#296/#297 files, models, activation,
execution policy, domain/state, webapp, or target-capable code is modified.

## Safety

Pure in-memory parser/authorization-boundary proof. No DNS, sockets/HTTP,
target interaction, scanning, execution, remediation/retest execution,
deployment, verdict creation, or attack-path mutation.
