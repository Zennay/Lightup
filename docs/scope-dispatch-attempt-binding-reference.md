# Dispatch attempt binding — offline reference only

This file accompanies `tests/test_scope_dispatch_attempt_binding_reference.py`.

## Contract

A scope decision must not be reusable across dispatch attempts. Before **each**
dispatch, the owning production gate must verify a trusted issuer-owned grant
against the exact tenant, request, current scope revision, grant identity and
unique attempt identifier. A changed attempt must require a fresh authorized
decision, even when all other fields are identical.

The offline reference deliberately rejects inactive grants, non-boolean
approval flags, malformed identifiers, subclasses of the grant envelope, and
revision type confusion. It treats matching values as **necessary but not
sufficient**: an attacker can fabricate every reference field.

## Ownership and safeguards

- This model is **not connected** to the executor and does **not** issue,
  persist, revoke or authorize grants.
- Production owner PR #107 must obtain grant data from an authenticated,
  issuer-controlled source; compare its live revision and revocation state
  immediately before every real dispatch and on retries; and prevent a
  previously accepted attempt token from being replayed.
- Use cryptographically unpredictable attempt identifiers or issuer-enforced
  monotonically unique identities, stored and consumed atomically. Mere
  equality with a caller-provided string does not prevent replay.
- Concurrency, cancellation, idempotency, expiry, approver separation, risk
  caps and tamper-evident audit remain **production integration requirements**.
- No real targets, DNS, network operations, scans, or tool execution are
  performed by this reference.

## Offline check

```sh
python -m unittest discover -s tests -p 'test_scope_dispatch_attempt_binding_reference.py' -v
```

Keep this contribution in draft until exact-head hosted and canonical
self-hosted checks succeed and the source owner reviews integration.
