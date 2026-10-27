# Accept-Encoding is non-authoritative (offline contract)

This branch adds an isolated **synthetic reference** for the scope authorization
boundary. HTTP `Accept-Encoding` describes transfer-content encoding preferences,
not tenant ownership, request approval, asset entitlement, capability approval,
purpose, grant status, or grant revision.

## Invariants

1. A matching *synthetic* authorization state remains unchanged for any
   `Accept-Encoding` value, including unknown, malformed and hostile objects.
2. Missing, unverified, inactive, noncanonical or mismatched authorization
   data must fail closed regardless of compression preferences. Even matching
   malformed identities, polymorphic dictionaries and type-confused grant
   revisions are rejected.
3. The policy must never stringify, coerce, traverse or invoke a header value.
4. Authorized identity comprises exact builtin string tenant, request, asset,
   capability, purpose and exact nonnegative integer revision.
5. HTTP compression hints cannot mint, upgrade, restore, revoke or delegate
   authorization. They do not form an authorization input.

## Offline preflight

```sh
python -m unittest tests/test_scope_accept_encoding_nonauthority_reference.py -v
```

No DNS, network calls, target interaction, assessments, activation, privileged
execution or deployment are performed by this test file.

## Limits and integration gate

The reference predicate is deliberately stand-alone. A passing result **does not**
prove the production executor, active grant provenance, revocation lifecycle,
or HTTP boundary is secure. No production executor modifications are included.

Keep the PR in draft until exact-head Python 3.11 and 3.14 validation, canonical
permanent VPS runner CI, and scope-owner review. Any actual production integration
requires an independently reviewed, fail-closed change and explicit authorization.
