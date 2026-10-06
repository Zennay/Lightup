# Remediation authoring-request direct structural integrity

`FutureRemediationAuthoringRequest` is a planning-only ST5 artifact. Its
constructor now enforces the same structural integrity contract as the strict
persisted handoff, in addition to the existing non-execution authority guards.

Direct construction requires:

- the exact authoring-request schema version;
- non-empty client, current-twin, future-twin and changeset identifiers;
- non-negative exact integers for twin versions and `item_count`;
- canonical lowercase SHA-256 values for report, plan, bundle and request
  digests;
- a non-empty tuple of exact `FutureRemediationAuthoringRequestItem` values;
- unique, canonically ordered item identities;
- `item_count == len(items)`;
- the canonical request SHA-256 recomputed from the complete bounded request
  metadata and items.

The builder and direct constructor share one canonical request-digest helper so
there is no separate payload definition that can drift. Persisted parsing still
performs its own duplicate-key-safe decode and live lineage validation; direct
constructor integrity does not replace that consumer boundary.

This change narrows integrity only. It adds no model execution, target
interaction, remediation execution, retest execution, deployment authority,
future-state resolution, security verdict, or attack-path mutation.
