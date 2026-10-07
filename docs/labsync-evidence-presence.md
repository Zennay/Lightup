# Lab finding evidence-presence contract

Issue: #850

## Boundary

`persist_lab_findings()` bridges isolated-lab assessment output into durable
product findings. Every persisted finding must retain at least one evidence
reference so that Finding → Impact → Fix → Retest never becomes detached from
the evidence that justified the finding.

There are two canonical producer shapes:

- planner-driven assessments attach a finding-local `evidence_ids` list;
- the older single-lane baseline exposes one top-level `evidence_id`, used as
  a compatibility fallback.

## Current gap

When neither source yields a value, the current implementation passes an empty
tuple to `DomainStore.record_finding()`:

```python
evidence_ids = tuple(finding.get("evidence_ids", ())) or (
    (labrun_result["evidence_id"],) if "evidence_id" in labrun_result else ()
)
```

That creates a durable product finding with no evidence lineage at all.

## Acceptance contract

Before any durable finding write:

- one or more finding-local evidence references keep the planner-driven path
  green;
- the exact legacy top-level fallback keeps the single-lane path green;
- an explicitly empty local list may fall back to a valid top-level evidence
  ID;
- if neither source yields at least one evidence reference, persistence fails
  closed with `ValueError`;
- the rejected path must not call `DomainStore.record_finding()` and must not
  create or mutate any durable finding row.

This contract owns evidence **presence only**.

Reference shape/type/canonicality, blank values and duplicates are owned by
#848. Polymorphic retest-finding admission is owned by #849.

## Expected state

Expected RED on exact PR #184 head
`bc7242d5171856f69f2ec68d7b3cf06d64bbb938`.

The source owner can absorb a narrow non-empty evidence guard before
`record_finding()`. This sidecar intentionally does not modify
`src/lightup/labsync.py`.

## Collision boundary

This branch adds only:

- `tests/test_labsync_evidence_presence.py`;
- this contract document.

PR #184 retains all lab-sync source and durable-provenance ownership. No
domain/state schema, review pipeline, scope authorization, retest observation,
target-capable worker, deployment, verdict or attack-path source changes are
included.

## Safety

Temporary-SQLite, offline persistence-integrity proof only. No DNS/network
access, target interaction, evidence collection, capability execution,
remediation/retest execution, deployment, security verdict creation or
attack-path mutation.
