# Scope authorization: canonical CIDR acceptance

Issue: #296

This tests/docs-only contract is based on exact current `main`
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

## Boundary

Configured `ScopePolicy.explicit_networks` values must be canonical network
declarations. Security-sensitive policy parsing must not silently clear host
bits and thereby widen operator intent.

The regression covers both IP families:

- `8.8.8.8/24` must not silently become `8.8.8.0/24`;
- `2001:4860:4860::8888/64` must not silently become
  `2001:4860:4860::/64`.

Both forged policies are exercised against a *different* address inside the
silently broadened network, with a current authorization attached. This proves
the failure is policy canonicality rather than missing authorization.

Positive controls preserve:

- canonical IPv4 network semantics;
- exact IPv4 host intent through `/32`;
- exact IPv6 host intent through `/128`;
- out-of-network denial.

## Expected RED on current main

Current `ScopePolicy._networks()` uses `ip_network(item, strict=False)`.
The standard library therefore normalizes host-bit-bearing CIDRs to their
containing network rather than rejecting them.

The production fix belongs to the active `scope.py` source-owning
composition. This branch intentionally changes no production source.

## Collision boundary

Only these files are added:

- `tests/test_scope_canonical_cidr_acceptance.py`;
- this document.

No #290/#295 files, `src/lightup/scope.py`, domain/state, activation,
execution-policy, orchestration, webapp, or target-capable code is modified.

## Safety

Pure in-memory authorization-configuration narrowing. No DNS, sockets, HTTP,
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
