# Offline scope authorization: JSON revision numeric identity

This is an isolated **non-authorizing reference contract** for a prospective issuer-owned grant envelope, not a production implementation. The reference accepts a bounded exact JSON object with exact tenant and grant string identities and a positive JSON **integer token** revision (safe interoperable range 1..2^53-1).

## Fail-closed requirements for source owners

- Parse duplicate object members as invalid, not as last-wins or first-wins. Duplicate tenant, grant, revision, and unknown fields must not silently change identity.
- Refuse Python boolean values even though `bool` subclasses `int`; reject strings, arrays, null, fractional/exponent JSON number tokens, nonfinite extensions and out-of-range revision integers.
- Enforce a single agreed wire schema across producer, persistence, verifier and dispatcher. Do not round, coerce or parse an exponential numeric spelling into grant revision identity. Keep denial on producer/consumer disagreements.
- On each dispatch, resolve the current tenant-scoped grant from an authenticated issuer-owned store; compare revision, authorization state, target, capability, risk, window and revocation against the current request. A parse-valid envelope is **never** permission.
- Perform durable single-use or attempt consumption atomically where relevant and preserve denial/audit evidence; do not use this reference to activate scanners, assess targets or relax scope controls.

## Test

`python -m unittest discover -s tests -p 'test_scope_numeric_json_revision_reference.py' -v`

Twelve stdlib-only test methods; no production imports, socket calls, target interaction or deployment. These checks prove reference behavior only. Before promotion require exact-head hosted Python 3.11/3.14 and canonical permanent self-hosted VPS validation, plus owning PR #107/source-owner review. This work does not modify #107 executor, approval/revocation owners or any existing scope branch.
