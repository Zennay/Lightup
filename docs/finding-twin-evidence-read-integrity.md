# Finding evidence read integrity at Security Twin projection

Issue #882 is a tests/docs-only consumer proof above the persisted finding-read
contract in #856.

## Boundary

A durable finding reaches the current Security Twin through:

```text
SQLite findings.evidence_ids_json
  -> DomainStore.list_findings()
  -> FindingRecord.evidence_ids
  -> project_current_twin()
  -> verified TwinFact / TwinRelationship / AttackPath lineage
```

The projection currently strips, sorts and deduplicates evidence references.
That transformation is acceptable only for already-canonical domain records.
It must never act as a repair boundary for producer-impossible persisted rows.

## Required behavior

Once #856 is absorbed by the finding-read source owner:

- canonical JSON arrays remain readable and project normally;
- canonical evidence order/value semantics survive into verified attack-path
  lineage;
- JSON strings, objects, mixed arrays, blank references and duplicate
  references fail at the domain read boundary before projection can normalize
  them;
- failed projection is read-only and leaves the persisted evidence JSON
  unchanged byte-for-byte.

## Non-overlap

This child changes no production source. In particular it does not modify:

- `src/lightup/domain.py` (#828 / #856 source ownership);
- `src/lightup/twin_projection.py`;
- `src/lightup/twin.py`;
- labsync evidence intake (#854);
- finding write-side evidence validation (#857);
- target interaction, remediation/retest execution, deployment or verdict code.

## Safety

The regression uses only temporary SQLite state and in-process Security Twin
projection. It performs no DNS/network I/O, target interaction, evidence
collection, capability execution, remediation/retest execution, deployment,
verdict creation or attack-path mutation.
