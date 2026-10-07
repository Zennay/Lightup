# Finding evidence read-integrity acceptance pack

Preferred branch-only evidence-remediation acceptance head for issue #885.

## Included contracts

- #856: strict persisted `findings.evidence_ids_json` decoding at the common
  `FindingRecord` read boundary.
- #882: the real `project_current_twin()` consumer cannot repair corrupt
  persisted finding evidence into verified Security Twin lineage.
- #883: engagement-scoped, client-scoped and operator-wide finding reads all
  cross the same fail-closed evidence decoder.

## Promotion rule

This branch is intentionally tests/docs only and may remain expected RED until
the #856 source successor can safely absorb the decoder after #828's active
`src/lightup/domain.py` ownership clears.

Do not weaken the tests by moving normalization into the projection. The source
repair belongs at the durable row -> `FindingRecord` boundary so every
consumer receives only canonical evidence.

## Non-overlap and safety

No production source, target interaction, network I/O, evidence collection,
capability execution, remediation/retest execution, deployment, verdict
creation or attack-path mutation is introduced.

Do not open a duplicate PR or canonical workflow while the shared permanent VPS
lane is occupied; preserve this branch as the preferred future absorption head.
