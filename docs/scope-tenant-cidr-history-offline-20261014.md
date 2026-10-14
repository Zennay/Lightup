# Offline tenant CIDR version history — transient widening HOLD

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCANS.**

This third opt-in, local-only tool reviews a short **self-reported**
sequence of tenant network inventories. It rejects expansions,
tenant reassignments and newly added scopes in **every adjacent
revision**, even if a later revision reverts the change.

## Format

One strict ASCII JSON object (at most 32,768 bytes) with exactly:

```json
{
  "schema_version": 1,
  "versions": [
    {"schema_version": 1, "networks": [
      {"tenant_id": "ALPHA", "scope_id": "NET1", "cidr": "10.0.0.0/24"}
    ]},
    {"schema_version": 1, "networks": [
      {"tenant_id": "ALPHA", "scope_id": "NET1", "cidr": "10.0.0.0/25"}
    ]}
  ]
}
```

Exactly **2–4 versions**, each 1–64 canonical IPv4 RFC1918 /
assigned IPv6 ULA CIDRs with no internal overlaps. Each step
must retain existing tenant-scope pair identity and never widen,
move or expand an existing CIDR. Entries may be removed, but not
reintroduced as an apparent new grant. Any invalid intermediate
snapshot or any temporary widening gives **whole-input HOLD**
without partial success.

```sh
python3 -m unittest discover -s tests -p 'test_scope_tenant_cidr_history_offline.py' -v
```

Result is a privacy-minimal, fixed-schema JSON receipt with
HOLD or REVIEW_ONLY and five authority fields fixed to false.
Neither original CIDRs nor tenant labels are echoed. Both
CLI statuses are nonzero: REVIEW_ONLY **3**, HOLD **2**,
so `review && scan` cannot succeed.

**Important:** Caller controls both the contents **and the
number/order of supplied versions**; any omitted or falsified
history goes undetected. The checker does **not** verify chain
signatures, provenance, ownership, customer permissions, real
tenants, grants, scope, allowed tool capabilities, time windows,
revocation, network isolation or safe routing. It never grants
authority to test a target, even if REVIEW_ONLY is returned.

No network, target, socket, DNS, database writes, scanning,
existing production source, workflow, runner or deployment.
All real source ownership remains with
[PR #100](https://github.com/Zennay/Lightup/pull/100).
Require actual permanently registered VPS evidence, exact-head
hosted unit+producer validation, independent security/privacy
review, latest-main integration and explicit human approval
prior to any production release.

**DRAFT/HOLD · NO MERGE · NO DEPLOY · NO REAL TARGETS.**
