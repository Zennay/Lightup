# ST5 implementation-plan review integrity pack

This branch composes five independent tests/docs-only acceptance slices directly above the exact branch-only #283 handoff head `996fa91daac86136caf2dc0c900c2edd84a0703b`.

## Included contracts

- exact raw JSON input type;
- exact persisted mapping object type;
- exact persisted scalar types;
- exact review schema/check value types;
- deterministic detached snapshot isolation.

## Composition boundary

The pack adds only the ten existing regression/contract files from the four 2026-10-07 exact-type branches plus the snapshot-isolation pair from the existing 2026-10-06 branch, and this manifest. It does not copy the separate review-chain invariant from that older stacked branch.

#283 retains strict handoff source ownership. #281 reviewer source, #327 reviewer-provenance hardening, #483 reviewer producer atomicity, #493 live-validation atomicity, revision-request/revised-plan work, scope authorization, gateway behavior, target-capable code, remediation/retest execution, deployment, verdicts and attack paths remain untouched.

## Expected validation state

The four exact-type branches are expected-RED acceptance proofs until #283 absorbs their fail-closed type guards. Snapshot isolation is the green control.

Do not start duplicate CI only to reproduce the known expected-RED cases, and do not treat this pack as promotion-ready while those contracts remain unresolved.

## Safety

Persisted planning-review integrity tests and documentation only. No model invocation, target interaction, scanning, tool execution, remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
