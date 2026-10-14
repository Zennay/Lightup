# Offline tenant CIDR transition: deny new scopes or network widening

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/REAL SCANS.**

This optional additional checker compares two complete, **caller-supplied**
tenant CIDR inventories. Both snapshots must separately pass the
strict canonical bounded IPv4/IPv6 disjoint-network review from
`scripts/check_scope_tenant_cidr_disjoint_offline.py`; one invalid
record anywhere makes the entire transition HOLD.

A proposed snapshot is only `REVIEW_ONLY` if every `(tenant_id, scope_id)`
already existed in the old snapshot and its new CIDR is a **subnet of
its own previous CIDR**, with the same IP version. Dropping a declared
scope, retaining the same range or reducing the network range is
syntactically reviewable. Adding a scope, switching tenant association,
changing IP family, moving to a different network, increasing a prefix
coverage or introducing any cross-tenant overlap causes atomic HOLD.

## Strict input (max 32,768 ASCII JSON bytes)

```json
{
  "schema_version": 1,
  "previous": {
    "schema_version": 1,
    "networks": [
      {"tenant_id": "ALPHA", "scope_id": "LAB", "cidr": "10.20.0.0/24"}
    ]
  },
  "proposed": {
    "schema_version": 1,
    "networks": [
      {"tenant_id": "ALPHA", "scope_id": "LAB", "cidr": "10.20.0.0/25"}
    ]
  }
}
```

Only the exact named keys are accepted. Both nested documents
independently require 1–64 exact tenant/scope/CIDR records with
canonical RFC1918/assigned fd00::/8 lab syntax. Neither address
class nor a syntactically nonwidening transition proves actual
ownership, trusted chronology, previous inventory authenticity or
customer consent.

```sh
python3 -m unittest discover -s tests -p 'test_scope_tenant_cidr_narrowing_offline.py' -v
```

A fixed minimal JSON receipt contains HOLD or REVIEW_ONLY, a
non-identifying reason and five **false** authority flags. It
does not print tenant names, IP addresses or customer references.
**REVIEW_ONLY exits 3, HOLD exits 2**, intentionally preventing
`review && scan` chaining. Both statuses are non-authorizing.

## Deliberate limitations

The entire `previous` snapshot is **untrusted** and may be fabricated
or incomplete. This cannot be a trusted revision history or rollback
prevention by itself. A source owner must independently verify actual
asset custody, authenticated client grant, tenant lineage, exact
capability/risk, allowed time window, revocation, resolver/routing
and explicit consent at the real execution gate. Real network
isolation cannot be inferred from CIDR labels alone.

No network, sockets, DNS, real targets, scanners, grants, persistent
state, source-owner files, workflows, runner or deployment changed.
Original source authorization remains with
[PR #100](https://github.com/Zennay/Lightup/pull/100).
Separate exact-head hosted Python3.11/3.14, genuinely registered
VPS CI, independent security/privacy/source-owner review, current-main
composition and **explicit human approval** remain release gates.

**DRAFT/HOLD · NO MERGE · NO DEPLOY · NO REAL SCANS.**
