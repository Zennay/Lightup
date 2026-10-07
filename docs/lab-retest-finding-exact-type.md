# Lab retest exact FindingRecord boundary

Issue: #849  
Parent source owner: #184 at `bc7242d5171856f69f2ec68d7b3cf06d64bbb938`

## Gap

`retest_finding()` reloads the durable finding before observation and rejects
stale/forged values, but it currently reads the caller object's `title` and
selects a baseline check before the durable equality guard.

A producer-impossible `FindingRecord` subclass can therefore expose a
different known check title and spoof equality with the durable record. The
function can retain the forged check identity even after replacing the caller
object with the canonical persisted finding.

## Required contract

Retest admission must require an **exact built-in `FindingRecord` instance**
before any caller-controlled finding field is used to choose a check or before
`http_baseline.observe()` can run.

The regression proves that:

- an equality-spoofing subclass is rejected;
- the rejected object cannot select a different known baseline check;
- no observation is invoked;
- the caller object is unchanged;
- the durable finding row and retest status are unchanged.

The exact canonical `FindingRecord` behavior remains owned by #184.

## Collision boundary

This branch is tests/docs only. It does not modify `src/lightup/labsync.py`,
domain/state schema, finding persistence/read ownership, review-pipeline
ownership, scope authorization, workers, or any target-capable source.

## Safety

Offline admission-integrity proof only. Observation is mocked in the adversarial
case. No real network/target interaction, evidence collection, remediation or
retest execution, deployment, verdict creation, or attack-path mutation.
