# ST5 implementation-plan review persisted-canonicality pack

This branch composes five independent tests/docs-only acceptance slices directly above the exact branch-only #283 handoff head `996fa91daac86136caf2dc0c900c2edd84a0703b`.

## Included contracts

- exact raw JSON input type (#598);
- exact persisted top-level mapping type (#603);
- exact persisted scalar types (#605);
- exact review schema/check container, key and value types (#608);
- canonical persisted verifier model identity with no surrounding-whitespace normalization (#667).

## Composition boundary

The pack copies only the ten existing regression/contract files from their source acceptance branches plus this manifest. No `src/lightup/**` file is changed.

#283 retains strict handoff source ownership. Snapshot isolation, live validation, reviewer/provenance source, producer atomicity, revision-request/revised-plan work, scope authorization, gateway behavior, target-capable code, remediation/retest execution, deployment, verdicts and attack paths remain untouched.

## Expected validation state

The exact-type and model-identity slices are acceptance contracts against the pinned #283 source. Known producer-valid controls remain green while the fail-closed adversarial cases are expected RED until the #283 source owner absorbs the corresponding guards.

Do not start duplicate CI merely to reproduce known expected-RED cases. Keep this composition branch PR-less while permanent LightUp self-hosted capacity is occupied.

## Safety

Persisted planning-review integrity tests and documentation only. No model invocation, target interaction, scanning, tool execution, remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
