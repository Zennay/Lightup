# Scope authorization: correlation IDs are not grants (offline reference)

Phase: M7/ST5 fail-closed hardening. This document is an **acceptance proposal**, not runtime policy or deployed authorization.

A diagnostic correlation/trace identifier helps operators associate denial logs and review receipts. It MUST NOT be accepted as consent, grant lineage, capability approval, tenant identity, asset ownership, review attestation, or scope authorization. A matching correlation ID across two requests cannot authorize reuse of the first request's approval. A changed/missing correlation ID alone cannot widen a denied operation.

Before dispatch, the owning production executor (#107) must independently evaluate issuer-trusted live approval/grant lineage, exact tenant and asset identity, capability and risk limits, expiration/revocation, and operator approval as applicable. Logging must not leak secrets or raw credentials. Correlation IDs are untrusted observability metadata, never inputs for constructing grants.

## Non-authoritative example tests

`tests/test_scope_correlation_non_authority_20261008.py` uses a pure synthetic decision model; it checks that identical, altered, privileged-looking or empty trace IDs never turn a denied decision into an allowed one; mismatched tenant and scope remain denied; truthy booleans and subclass impersonation fail closed. Its one positive example is conditional only and **does not establish authenticated issuer lineage**.

## Integration and release requirements

Owner #107 must review and bind these cases to the actual admission and dispatch paths. Require exact-head hosted and permanent VPS test results, independent human review and correct audit retention before promotion. Do not infer production compliance from standalone fixture success. No DNS, target contact, sockets, scans, capability execution, authorization writes, deployment or activation are involved.
