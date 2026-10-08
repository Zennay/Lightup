# ScopePolicy offline denial regression pack

This additive test pack pins the existing `ScopePolicy.decide` fail-closed boundary without changing production implementation, adding active testing, or authorizing any target.

The five deterministic cases cover: expired authorization for an explicitly listed public IPv4 network; not-yet-valid authorization for a normalized explicit hostname; private-address refusal with private lab mode disabled; missing authorization for an explicitly listed public IPv6 network; and refusal of a different hostname even when the request carries an otherwise-current authorization.

Run with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_policy_denial_regressions.py' -v`.

These tests use documentation-only addresses and local in-memory objects. No DNS, HTTP, discovery, scanning, exploitation, assessment execution, real targets, production permissions or deployment is involved. The tests assert only the present scope-policy behavior, **not** sufficient end-to-end authorization for a real assessment. Existing product-domain grant, tenant binding and live-resolver gates remain mandatory.

Ownership: only `tests/test_scope_policy_denial_regressions.py` and this document. Parallel work on `ToolExecutor`, discovery, grant persistence, scope implementation, and production authorization sources is intentionally untouched.
