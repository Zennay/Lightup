# Remediation authoring-request direct-construction integrity

`FutureRemediationAuthoringRequest` is a bounded ST5 planning artifact. Its
constructor now enforces the same top-level metadata and digest invariants as
the strict persisted handoff, rather than depending on a later consumer to
notice forged in-memory state.

Direct construction requires:

- the exact authoring-request schema version;
- non-empty client, current-twin, future-twin and changeset identifiers;
- non-negative integer twin versions and item count, with bool/int confusion
  rejected;
- canonical lowercase SHA-256 report, plan, bundle and request digests;
- a non-empty tuple of exact `FutureRemediationAuthoringRequestItem` values;
- unique item identities in canonical order;
- `item_count == len(items)`;
- the existing plan-only lifecycle and authority stop line;
- a request SHA-256 that recomputes exactly from all canonical request metadata
  and nested item/evidence lineage.

Changing a nested item while retaining the old request digest therefore fails
at construction, before serialization or later live-lineage validation.

This is integrity narrowing only. It adds no target interaction, tool execution,
remediation execution, retest execution, deployment authority, future-state
resolution, security verdict, or attack-path mutation.
