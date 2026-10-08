# Scope authorization envelope resource bounds — offline reference

This independent M7/ST5 reference tests *resource admission only*. It cannot
issue consent, approve an asset, resolve a live grant, dispatch a capability,
or prove production security. Do not promote from successful shape validation
to executable authorization.

Proposed owner-reviewed contract:

- Apply a strict encoded-byte ceiling **before decoding or parsing**.
- Reject invalid UTF-8, JSON duplicate members, nonfinite numeric constants,\n  **and finite-looking numeric literals that overflow to infinity** (e.g. `1e999`),
  and non-object outer envelopes.
- Bound container nesting and total traversed nodes, without recursive walking.\n- Reject zero, negative, Boolean, non-integer or missing budget configuration; do not silently interpret `true` as integer `1`.\n- Use inclusive ceilings: precisely-at-budget input is structurally eligible, while the next byte, node or depth level must be denied.\n- Reject parser recursion failures rather than allowing them to escape into runtime dispatch.\n- Reject duplicate members at every nesting level (including JSON-escaped duplicate names), trailing JSON documents, empty/whitespace-only bodies, and UTF-8 BOM.\n- Count root objects, nested containers, and scalar values toward node limits; depth and node ceilings are inclusive.
- Treat a parser failure, oversized body, or exhausted budget as denial.
- Keep this check independent of the authorization decision: the production
  executor must still revalidate trusted issuer lineage, tenant, asset,
  capability, scope, clock, revocation, and risk at execution time.
- Resource-limit constants are illustrative and require explicit product
  review; this reference does **not** establish deployed API limits.

Run: `python -m unittest discover -s tests -p 'test_scope_envelope_resource_bounds_reference_20261008.py' -v`

Ownership: PR #107 owns production executor logic. Existing JSON-ambiguity
reference #1002 owns duplicate-member semantics. This file independently
tests envelope resource exhaustion and is not a replacement for that work.
No network, real targets, or activation.
