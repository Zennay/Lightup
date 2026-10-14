# Cross-binding of tenant lab inventory and scheduled UTC windows

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCANS.**

The opt-in `scripts/check_scope_tenant_inventory_schedule_binding_offline.py`
checks whether **one self-declared lab CIDR inventory** and **one
self-declared UTC window schedule** refer to exactly the same
`(tenant_id,scope_id,cidr)` records. It is a non-authorizing,
offline consistency check, not a trusted asset inventory, signed
calendar, client consent, live grant or execution gate.

## Input

Strict bounded ASCII JSON, maximum 32768 bytes and exactly:

```json
{
  "schema_version": 1,
  "inventory": {"schema_version": 1, "networks": [
    {"tenant_id": "ALPHA", "scope_id": "LAB", "cidr": "10.20.0.0/24"}
  ]},
  "schedule": {"schema_version": 1, "windows": [
    {"tenant_id": "ALPHA", "scope_id": "LAB", "cidr": "10.20.0.0/24",
     "starts_at": "2026-10-14T08:00:00Z",
     "ends_at": "2026-10-14T09:00:00Z"}
  ]}
}
```

Both documents must independently pass the strict lab network
disjointness and time-window overlap reviews. Every inventory
network must have exactly one identical scheduled
`tenant_id/scope_id/cidr` triple, and every scheduled triple
must be present in the inventory. No missing, extra, renamed
tenant/scope, widened, narrowed or changed CIDR is silently accepted.
Untrusted source labels and periods are never copied into outputs.

Run synthetic acceptance:

```sh
python3 -m unittest discover -s tests -p 'test_scope_tenant_inventory_schedule_binding_offline.py' -v
```

The output always uses a fixed privacy-preserving schema and all five
authority flags are **false**. REVIEW_ONLY returns nonzero **3**,
HOLD nonzero **2**. Thus even matching plans do not allow
`review && scan` to execute. No DNS, sockets, customer targets,
permissions, database reads/writes, active tools, integrations
or deployments occur.

**Key caveat:** Both inventory and schedule are attacker-editable,
self-declared text. Matching records neither proves actual lab
ownership nor customer consent, a permitted test window, a live
authorized asset/grant, revocation state or trustworthy time source.
Independent source owner [#100](https://github.com/Zennay/Lightup/pull/100),
security/privacy review, exact-current-HEAD hosted and permanently
registered VPS test evidence, latest-main integration, and explicit
human release are separate blockers.

**DRAFT/HOLD · NO MERGE/DEPLOY/REAL TARGET EXECUTION.**
