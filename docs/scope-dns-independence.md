# DNS-independent scope authorization

LightUp treats scope authorization as a local, syntactic policy decision. DNS, resolver state, split-horizon configuration, rebinding behavior, or socket connectivity must never create authority.

## Invariant

`ScopePolicy.decide()` may derive authority only from:

- the normalized target host or literal IP supplied in the request;
- loopback/private-lab rules;
- explicit host or network policy entries;
- the target's current authorization metadata.

It must not call DNS or socket-resolution APIs while classifying scope.

## Why this matters

If scope classification depended on name resolution, mutable DNS could change the authorization meaning of an otherwise unchanged target. An unknown hostname could be made to resolve to loopback/private space, or an explicitly authorized name could later resolve somewhere unintended. Authorization therefore stays bound to the declared policy identity, not to resolver answers.

## Regression contract

`tests/test_scope_dns_independence.py` blocks common Python resolver and socket-opening entry points and proves that:

1. an unknown hostname remains `OUT_OF_SCOPE`;
2. an explicitly allowed hostname is evaluated by normalized identity only and still requires a current authorization;
3. a literal address in an explicit network is classified locally;
4. `localhost` is a syntactic special case, not resolver-derived trust.

The tests are offline and in-memory. They do not resolve DNS, open sockets, scan targets, or widen activation/execution authority.
