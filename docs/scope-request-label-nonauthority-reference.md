# Scope authorization: request labels are non-authoritative

## Scope

Offline reference for a proposed authority boundary: a human-readable assessment request label or title is presentation metadata, not authorization evidence. It must not substitute for tenant, request, asset, capability, purpose, or explicit approval.

## Proposed invariants

- Authorization decisions compare canonical tenant/request identity, purpose, asset, capability and explicit boolean approval.
- A label saying `approved`, `active`, or imitating an authorized identity neither grants nor revokes authority.
- If any identity or authorization field differs, matching text in the label cannot repair it.
- Labels can change without changing an otherwise identical authorization decision.
- No implicit coercion of approval values such as `"true"`.
- Grant asset/capability entries must be exact bounded ASCII identity strings; malformed or polymorphic entries are not authority; tuple subclasses with overridden containment are rejected.
- Polymorphic request envelopes cannot substitute for canonical request instances.
- A request/grant reference is not trusted provenance: this standalone predicate only illustrates the boundary.

- Unicode grant identities and control-character payloads fail closed regardless of the request label.

## Proof surface

`tests/test_scope_request_label_nonauthority_reference.py` contains sixteen Python stdlib unittest methods. Execute offline with:

```sh
python -m unittest discover -s tests -p 'test_scope_request_label_nonauthority_reference.py' -v
```

## Ownership and activation

This is **not** an implementation of verified grants or production permission. Existing source owners retain authorization issuance, approval provenance, live revalidation, revocation, and dispatch. Before integration, the production owner must confirm the approved canonical fields and add acceptance tests to the actual execution boundary.

This change is tests/docs only: no DNS, network, target interaction, active capabilities, scanner invocation, deployment, grant activation or authority widening. Preserve draft status until exact-head hosted Python 3.11/3.14 and canonical permanent-VPS validation plus source-owner review.
