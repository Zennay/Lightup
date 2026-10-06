# Scope authorization: atomic explicit-host entry validation acceptance

Issue: #297 follow-up

This tests/docs-only follow-up is based on exact current `main`
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

## Boundary

Issue #297 requires public scope configuration to be validated as one coherent
policy before *any* public allow decision. The first acceptance proof covered a
malformed network declaration bypassed by the hostname path.

This follow-up covers the reverse direction: malformed explicit-host
configuration must not be skipped merely because the current target is an IP
literal and the explicit-network path would otherwise allow it.

A runtime `frozenset({123})` satisfies neither the declared
`frozenset[str]` contract nor a valid host identity. With a valid
`8.8.8.8/32` network and public-auth requirement disabled, current main never
touches `explicit_hosts` on the IP path and therefore grants the target.

The required result is a fail-closed type/configuration error before the allow
decision. Canonical host + network configuration remains a green control.

## Collision boundary

This branch adds only:

- `tests/test_scope_policy_atomic_host_entry_validation_acceptance.py`;
- this document.

It does not modify `src/lightup/scope.py`, the already-proven #292/#296/#297
network-policy branch, #367/#368 policy-text contracts, models, activation,
execution policy, domain/state, webapp, or target-capable code.

## Safety

Pure in-memory authorization-configuration integrity proof. No DNS, sockets,
HTTP, target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
