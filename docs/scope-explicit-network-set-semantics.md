# Explicit-network set semantics

Issue: #290

This contract pins the authorization behavior of `ScopePolicy.explicit_networks`
without changing production code.

## Security invariant

The configured networks are treated as the exact union of their CIDRs. Matching
must not gain or lose authority because entries are reordered, duplicated, or
overlap. IPv4 and IPv6 membership remains family-specific.

For a public target inside that union, network membership is only the scope
classification step. It does not replace the existing requirement for current
authorization. A target immediately outside every declared CIDR remains out of
scope even when it carries a current authorization object.

## Regression coverage

`tests/test_scope_explicit_network_set_semantics.py` proves:

- first/last addresses inside an exact public CIDR follow the explicit-network
  path, while adjacent addresses remain out of scope;
- duplicate entries do not bypass the authorization requirement;
- network ordering does not change the resulting `ScopeDecision`;
- overlapping CIDRs do not mint authorization;
- IPv4 targets cannot match IPv6-only policy and IPv6 targets cannot match
  IPv4-only policy;
- a canonical public IPv6 target inside an explicit network still requires
  authorization and then resolves to `EXPLICIT_NETWORK`.

## Safety boundary

The tests are pure in-memory calls to `ScopePolicy.decide()`. They perform no
DNS resolution, socket or HTTP I/O, scanning, target interaction, tool
execution, remediation/retest execution, deployment, or attack-path mutation.

This slice intentionally does not modify `src/lightup/scope.py` or any active
scope/activation/execution-policy/domain branch. It is a regression contract
only and must remain branch-only until exact-head hosted and canonical
self-hosted proof are available.
