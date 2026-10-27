# Public target authorization window regression contract

This patch adds tests against the **existing** `lightup.scope.ScopePolicy`, not an independently invented authorization predicate.

## Coverage
- Explicitly listed public host/IP without authorization is rejected.
- Expired or future-dated synthetic grants are rejected.
- Listed public host/IP with currently dated synthetic grant reaches the existing policy's explicit-match decision.
- An unlisted public host/IP remains out-of-scope even with a grant fixture.
- Userinfo spoofing cannot redirect an explicit hostname allowlist match to a different parsed host.

## Critical security limitation
`Authorization(owner, reference, ...)` is only a data object: it does **not** cryptographically authenticate consent, issuer identity, tenant, capability, or asset binding. A passing allowlist decision is **not** proof that a production assessment may execute. No real-world permission is created here. The production dispatcher must enforce signed/verified authorization, target/capability/tenant binding, risk approval, revocation, and a fresh dispatch-time decision before any target I/O. No active target mode is enabled by this change.

## Test and release gates
Run `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_public_authorization_window_20261009.py' -v` on Python 3.11 and 3.14. Require exact-head canonical permanent VPS CI success, then scope-owner review; keep the pull request draft until these gates pass. Tests are offline and do not open sockets or resolve DNS.
