# Scope authorization: atomic public-policy validation acceptance

Issue: #297

This tests/docs-only contract is based on exact current `main`
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

## Boundary

A public `ScopePolicy` must be valid as one coherent authorization boundary
before any public host or network can be allowed.

Today `explicit_networks` is parsed lazily only on the IP path. A malformed
network declaration can therefore coexist with an allowlisted hostname and be
skipped entirely when that hostname is evaluated.

The regression proves the malformed network cannot be bypassed:

- with the normal current-authorization requirement enabled;
- when that public-authorization gate is explicitly disabled.

Canonical host + canonical network configuration retains the existing positive
host and network decisions.

## Expected RED on current main

A policy containing:

- `explicit_hosts={"security.example.test"}`;
- `explicit_networks=("not-a-cidr",)`;

currently allows the explicit hostname without ever calling `_networks()`.
Both rejection tests therefore fail until policy validation is made atomic.

## Collision boundary

This branch adds only:

- `tests/test_scope_policy_atomic_validation_acceptance.py`;
- this document.

It does not modify `src/lightup/scope.py`, #290/#295/#297 owner source,
domain/state, activation, execution-policy, orchestration, webapp, or
target-capable code.

## Safety

Pure in-memory authorization-configuration integrity proof. No DNS, resolver,
sockets/HTTP, target interaction, scanning, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
