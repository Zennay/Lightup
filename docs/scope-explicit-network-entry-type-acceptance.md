# Scope authorization: explicit-network entry type acceptance

Issue: #292

This is a tests/docs-only acceptance contract from exact current `main`
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

## Boundary

`ScopePolicy.explicit_networks` is a security-sensitive authorization input.
Every entry must be an exact non-empty string before it reaches Python's
`ip_network()` parser.

Python's standard parser accepts several non-string values as real network
identities. Runtime type confusion must therefore fail closed rather than mint
public network membership.

The regression covers:

- integer `134744072`, which is interpreted as `8.8.8.8/32`;
- raw four-byte input for `8.8.8.8`;
- boolean values, which are integer subclasses;
- `bytearray` input;
- the unchanged positive path for canonical string `8.8.8.8/32`.

`allow_private_lab=False` keeps these cases on the explicit-network path so
the regression cannot pass through private/lab classification instead.

## Expected RED on current main

Current `ScopePolicy._networks()` calls:

`ip_network(item, strict=False)`

without first requiring `type(item) is str`. At least the coercible
non-string cases can therefore become concrete networks and authorize a target
when a current authorization object is attached.

The intended fix belongs to the active source-owning scope composition. This
branch deliberately does not modify `src/lightup/scope.py`.

## Collision boundary

This branch adds only:

- `tests/test_scope_explicit_network_entry_type_acceptance.py`;
- this document.

It does not modify #290, active #100/#164 source ownership, scope/domain/state,
activation, execution-policy, orchestration, webapp, or target-capable code.

## Safety

Pure in-memory authorization-configuration validation. No DNS, sockets, HTTP,
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
