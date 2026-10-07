# ST5 revised-remediation review-request parser input purity

Issue #631 proves caller-input purity above strict revised-remediation review-request handoff #244 at exact parent head `7eb4f5f72f5656b5476ba8735d7e83ded06decf3`.

## Invariant

The direct persisted-object parser is a read-only consumer. It must preserve caller-owned state on success and on fail-closed rejection.

Both supported built-in producer forms remain part of the proof:

- `json.loads(request.to_json())`, with an exact built-in list for `required_checks`;
- `request.as_dict()`, with an exact built-in tuple for `required_checks`.

Successful parsing must preserve value content, root and rubric-container identity, top-level key ordering and rubric ordering. Repeated parsing of the exact same object must return the same typed request without mutation.

Failure paths must preserve the same caller-owned state after:

- a late review-request digest mismatch;
- a required-check rubric mismatch;
- an authority-widening rejection.

Repeated rejection must produce the same error without accumulating mutation.

## Separation from adjacent acceptance

This branch adds tests/docs only and does not modify #244 source.

- #626 owns persisted object-type exactness.
- #461 owns full live-validation atomicity.
- #464 owns builder input atomicity.
- #589 owns raw JSON text typing.
- #248 and its descendants own the revised review itself.

## Safety

This is a pure in-memory persisted-parser proof. It performs no model invocation, target interaction, code/config application, tool/remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
