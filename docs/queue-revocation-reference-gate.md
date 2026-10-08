# Queue-time revocation reference gate (offline)

This is an **independent executable reference model**, not LightUp production code, an integration test, or permission to contact targets. It does not import or modify the production executor.

The ten deterministic unittest cases cover revocation between enqueue and dispatch, retries after revocation, reapproval under a reused identifier, tenant-separated identifiers, absent live authority, unchanged valid model authority, invalid tenant selectors, isolated revocation of a different tenant, inter-step denial, and same-revision inactive replacement. No sockets, DNS, real handlers, scanners, credentials, or external services are used.

## Required production contract

- Persist a tenant-bound immutable authorization snapshot with every queued action.
- Resolve current authorization at **each** dispatch and retry; stale enqueue-time approval must not be reused.
- A newly issued grant (even with the same textual identifier) requires new run authority; compare immutable grant lineage/version, not ID alone.
- Denial must happen before any target-capable handler or success-evidence side effect.
- Production owner PR #107 must integrate and verify the real executor; PR #983 owns the broader transition fixture; PR #982 owns release receipts. This branch claims **none** of those checks passed.
- In-flight cancellation, evidence persistence, durable queue concurrency, expiry/time windows, and crash recovery are **not** modeled here. They require separate source-owner integration tests on an exact commit, reviewed hosted CI and permanent VPS evidence.
- Green results for this model alone must never enable active-target execution.

Run locally without network access: `python -m unittest discover -s tests -p test_queue_revocation_reference_gate.py -v`.

## Reference-model limitation

Python dataclass equality compares field values; it is **not a secure grant-lineage primitive**. The production implementation must validate exact issuer-owned lineage, immutable authorized scope and revocation epoch, not trust an attacker-supplied equivalent object or integer revision. The tests do not demonstrate that stronger property. The inter-step test verifies only a newly dispatched model action, not asynchronous interruption of a running handler.
