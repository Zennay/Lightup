# ST5 remediation-text revision-proposal persisted object type exactness

Issue #625 isolates persisted-object type fidelity above strict remediation-text revision-proposal handoff #238 at exact parent head `ef38622caf8c63be34785f971d0526e85740b55d`.

## Contract

Both canonical built-in controls remain green: `json.loads(proposal.to_json())` and `proposal.as_dict()`. The direct parser must reject equivalent-content Python subclasses that persisted JSON cannot produce and must not normalize such values into trusted typed state.

The acceptance pack covers:

- the top-level mapping and every schema key;
- revision-request, prior-review, prior-proposal, prior-content, content and revision-proposal SHA-256 lineage;
- provider/model provenance;
- remediation content before `.strip()` normalization;
- schema/future/verdict fixed metadata.

Rejection must leave caller-owned input value-equivalent to its pre-call snapshot.

## Separation from existing owners

This branch adds tests/docs only and does not modify #238 source. #468 keeps producer atomicity, #456 keeps persisted live-validation atomicity, model/content and raw-JSON canonicality stay separate, #231/#624 own the revision request, and revised-review stages retain their own branches.

## Safety

Persistence-integrity acceptance only. No model invocation, target interaction, code/config application, tool/remediation/retest execution, deployment, verdict creation or attack-path mutation.

## Expected state

The exact #238 parser currently uses broad `isinstance`, schema equality, string/SHA helpers and `.strip()` content normalization. The new tests are intentionally expected RED until the source owner requires exact built-in persisted object/scalar types.
