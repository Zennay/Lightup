# Malformed URL authority must fail closed (red regression)

Scope-authorization acceptance contract for `ScopePolicy.decide()`.

Malformed URI authorities (including unmatched IPv6 brackets and invalid ports)
must return a denied `ScopeDecision` with `ScopeReason.INVALID_TARGET`.
They must never raise a parsing exception into an authorization caller, and must
never normalize to a different admitted hostname. The decision is a pure
in-memory operation; it may not perform DNS, HTTP, socket calls or target work.

A valid pre-existing public-host grant must **not** cause a malformed
authority such as `example.test:invalid` or `example.test:999999` to be
accepted. The hostname portion alone is insufficient to certify valid target
identity. This is an authorization-boundary regression, not just input
sanitization.

This branch intentionally owns **tests and documentation only**. Production
`src/lightup/scope.py` belongs to other parallel scope workers. The regression
is expected to be red on an implementation that propagates `urlparse` errors
or ignores malformed authority ports. A source owner may absorb the contract
and harden parsing while preserving existing explicit-host + authorization
requirements. In particular no public grantless access is permitted.

Run: `python -m unittest discover -s tests -p test_scope_malformed_authority_red.py -v`.
Do not merge until the contract becomes green and the exact head passes both
hosted/offline and canonical self-hosted CI.
