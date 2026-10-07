# Offline scope authorization admission matrix

This add-only test pack exercises `ScopePolicy.decide` against public assets without opening sockets, resolving DNS, or executing any capability.

## Invariants

1. An authorization object alone must never turn an unknown public host, public IPv4 address, or public IPv6 address into an allowed target.
2. Disabling automatic private-lab admission must deny unlisted private/link-local fixtures.
3. A listed public host requires an authorization grant that is currently valid; absent, future, and expired grants fail closed.
4. An explicit IPv4 network can admit its listed member only with a current grant, not an adjacent public address.

## DNS and URL authority contracts

- Explicit DNS admission is exact-host only: subdomains, suffix lookalikes, path/query mentions, and username/userinfo appearances cannot confer authority.
- Canonical host spellings (case and trailing dot) still require a live grant when the hostname is explicitly listed.
- These are parser/policy unit tests using synthetic `.test` domains; they never resolve a hostname or open a connection.

## Ownership / integration

- Additive paths only: `tests/test_scope_authorization_matrix_offline.py`, `tests/test_scope_exact_dns_allowlist_offline.py`, and this document.
- No production-source edits; do not replace active owners of `scope.py`, authorization models, `ToolExecutor`, or the registry.
- Run offline with `python -m unittest discover -s tests -p 'test_scope*offline.py' -v`.
- No live target, network I/O, active scan, deployment, or automatic activation is authorized by these tests.

## Acceptance

Both the fixture-only matrix and the repository's standard CI must pass on the GitHub self-hosted VPS runner before considering integration.
