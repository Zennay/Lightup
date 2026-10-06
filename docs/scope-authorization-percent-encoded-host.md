# Percent-encoded host scope-authorization contract

Issue: #366

LightUp keeps percent-encoded hostname text literal at the scope boundary.
Text that only *looks* like an allowlisted host or IP after percent decoding
does not inherit the authority of that decoded-looking identity.

This tests/docs-only contract freezes the following behavior:

- `security%2eexample%2etest` is not the explicit host
  `security.example.test`;
- an allowlisted hostname followed by an encoded dot plus attacker-controlled
  suffix does not inherit the allowlisted prefix's authority;
- `localhost%2e` and `127%2e0%2e0%2e1` do not gain loopback trust;
- percent-encoded public IPv4 text does not match an explicit CIDR;
- percent-encoded digits cannot manufacture a canonical loopback literal;
- canonical unencoded hosts and IPs keep their existing explicit-host and
  explicit-network semantics.

The regression uses only in-memory `Target`, `Authorization` and
`ScopePolicy` values. It performs no DNS lookup, socket connection, HTTP
request, scanning, tool execution, target interaction, remediation/retest,
deployment, verdict creation, or attack-path mutation.

## Why this is separate

This contract is deliberately narrower than neighboring scope work:

- #267 owns URL authority/userinfo/query/fragment separation;
- #285 owns Unicode/IDNA alias non-equivalence;
- #288 owns legacy/ambiguous numeric host aliases;
- #364 owns the rule that authorization cannot create missing scope membership.

Percent-encoded text stays a distinct syntactic identity here. Any future
percent-decoding or host canonicalization must be introduced deliberately and
consistently across target normalization, allowlists, authorization binding and
execution boundaries rather than appearing as an incidental parser change.

## Collision boundary

This slice adds only:

- `tests/test_scope_authorization_percent_encoded_host.py`
- `docs/scope-authorization-percent-encoded-host.md`

It does not modify production source, existing tests/docs, activation,
execution-policy, domain/state, orchestration, webapp, evidence-remediation, or
another active scope-authorization sibling.

## Promotion gate

Exact-head validation must pass before this contract is promoted. Keep it
branch-only if opening another canonical LightUp PR would amplify the current
self-hosted queue.
