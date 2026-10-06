# Scope authorization: offline resolution contract

Issue: #279

## Security invariant

Scope classification is an authorization decision, not a discovery step. `ScopePolicy.decide()` must therefore remain purely local and syntactic:

- it must not resolve hostnames;
- it must not open sockets;
- DNS answers must not promote an otherwise unknown hostname into loopback, private-lab, explicit-host, or explicit-network authority;
- an explicit authorized hostname is decided from its parsed authority host and configured policy, not from mutable resolver state;
- literal-IP and configured-network classification is performed locally;
- `localhost` is a syntactic local special case and does not require resolver trust.

This keeps the scope boundary independent from DNS rebinding, split-horizon DNS, resolver poisoning, local hosts-file changes, and transient network state.

## Regression contract

`tests/test_scope_authorization_offline_resolution_contract.py` blocks the common Python DNS/socket entry points while exercising the real scope policy. Any attempted network-facing resolution fails the test immediately.

The cases prove that:

1. an unknown hostname remains `OUT_OF_SCOPE` without DNS;
2. an explicitly authorized hostname is accepted as `EXPLICIT_HOST` without DNS;
3. an explicitly authorized public documentation-network literal is accepted as `EXPLICIT_NETWORK` without DNS or reverse lookup;
4. `localhost` remains `LOOPBACK` without DNS.

URL authority confusion, lookalike-host parsing, and userinfo/query/fragment bait are intentionally excluded here because they are owned by #267.

## Collision boundary

This slice is tests/docs only. It intentionally does not modify:

- `src/lightup/scope.py` or `src/lightup/models.py`, owned by active scope-authorization work;
- orchestration, activation, execution policy, engagements, webapp, workers, remediation, or planning source;
- active PR #100, #264, #267, or their owned files.

## Safety boundary

The tests are fully offline and in-memory. They do not contact targets, perform DNS lookups, create sockets, scan, execute capabilities, mint authority, run remediation/retests, deploy, or mutate attack paths.

The contract narrows trust: future scope implementations may refactor parsing, but they must not make resolver output part of the authorization decision.
