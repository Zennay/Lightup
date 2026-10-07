# ST5 revised-remediation review-request persisted object type exactness

Issue #626 isolates persisted-object type fidelity above strict revised-remediation review-request handoff #244 at exact parent head `7eb4f5f72f5656b5476ba8735d7e83ded06decf3`.

## Contract

Both supported built-in producer forms remain green:

- `json.loads(request.to_json())`, with an exact built-in list for `required_checks`;
- `request.as_dict()`, with an exact built-in tuple for `required_checks`.

Equivalent-content Python subclasses must fail closed at the direct-object persistence boundary. Coverage includes the top-level mapping and schema keys, revised-proposal/revision-request/prior-review/content/review-request SHA lineage, provider/model provenance, schema/future/verdict metadata, both supported rubric container types and every rubric string.

Rejection must leave caller-owned input value-equivalent to its pre-call snapshot.

## Separation from existing owners

This branch adds tests/docs only and does not modify #244 source. The raw JSON text-type branch, #464 builder atomicity, #461 persisted live-validation atomicity, #238/#625 revised proposal work, #248 reviewer work and target-capable paths remain separate.

## Safety

Persistence-integrity acceptance only. No model invocation, target interaction, code/config application, tool/remediation/retest execution, deployment, verdict creation or attack-path mutation.

## Expected state

The exact #244 parser currently accepts subclasses through broad `isinstance`, schema equality, string/SHA helpers and list/tuple coercion. The new tests are intentionally expected RED only for subclass values while both exact built-in producer forms stay green.
