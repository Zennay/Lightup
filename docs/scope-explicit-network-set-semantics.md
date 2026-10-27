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
- disabling the public-authorization requirement does not widen membership beyond the declared CIDR;
- malformed string CIDRs are not silently ignored, regardless of their position in the configured tuple;
- IPv4 targets cannot match IPv6-only policy and bracketed IPv6 authorities cannot match
  IPv4-only policy;
- a bracketed public IPv6 authority inside an explicit network still requires
  authorization and then resolves to `EXPLICIT_NETWORK`.

During validation, bare IPv6 input exposed a separate parser-boundary gap: current
schemeless parsing truncates the host token instead of preserving the full literal.
That behavior fails closed in the observed case and is tracked separately as #291.
Validation also found that non-string `explicit_networks` entries can be coerced by
`ip_network()` into real networks; that authority-minting type-confusion gap is tracked
as #292. This branch does not touch the actively owned `scope.py` implementation.

## Safety boundary

The tests are pure in-memory calls to `ScopePolicy.decide()`. They perform no
DNS resolution, socket or HTTP I/O, scanning, target interaction, tool
execution, remediation/retest execution, deployment, or attack-path mutation.

This slice intentionally does not modify `src/lightup/scope.py` or any active
scope/activation/execution-policy/domain branch. It is a regression contract
only and must remain branch-only until exact-head hosted and canonical
self-hosted proof are available.
