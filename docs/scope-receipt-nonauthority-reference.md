# Scope authorization: audit receipt is not authority (offline reference)

This isolated reference contract states that a successful audit/dispatch/CI receipt, an approval-looking correlation ID, or a persisted historical outcome must **never** be accepted as a new grant. Authorization must be recomputed from issuer-trusted, current, non-revoked, tenant/request/capability/revision-bound grant state for each dispatch and redispatch.

The companion stdlib-only test is illustrative and has **no connection to production**. Its positive control is conditional on a synthetic live grant; it does not authenticate provenance, enforce scope, risk, asset, time window or revocation from a real grant store. It cannot be used to activate TARGET_ACTIVE operations.

Acceptance for a future production owner: deny with no handler invocation, network I/O or evidence write when there is no current authenticated grant, even if the last audit receipt says "allowed"; mismatched grants and malformed active/revision fields also deny. Revocation, retries, queue replay, and eventual-consistency paths must not consult audit output as a substitute for live authority.

Ownership: tests/docs only. Do not modify active ToolExecutor (#107), policy (#100), approval, revocation, registry, target-capable worker, activation, or persistence source branches. No real assets, DNS, sockets or target interactions.

Validation: `python -m unittest discover -s tests -p 'test_scope_receipt_nonauthority_reference.py' -v`. Exact-head hosted Python and canonical permanent VPS CI are required before any promotion. This reference is not evidence of production enforcement.
