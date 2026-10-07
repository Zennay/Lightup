# ST5 remediation-text review-request persisted object type exactness

Issue #622 isolates a persistence-type boundary above strict remediation-text review-request handoff #215 at exact parent head `cee2e5391f32eed5212424d778c66cae73042e4a`.

## Contract

Both built-in producer forms supported by the handoff must remain green:

- `json.loads(review_request.to_json())`, where `required_checks` is an exact built-in list;
- `review_request.as_dict()`, where the dataclass preserves `required_checks` as an exact built-in tuple.

The direct `future_remediation_text_review_request_from_dict` path must reject equivalent-content Python subclasses rather than accepting or normalizing them.

The acceptance regression covers:

- the top-level mapping and all schema keys;
- schema/future/verdict metadata;
- request, bundle, proposal, content and review-request SHA-256 lineage;
- provider/model provenance;
- positive `item_count`;
- both supported built-in `required_checks` container types and every check-name string.

Rejection must leave caller-owned input value-equivalent to its pre-call snapshot.

## Separation from existing owners

This branch adds tests/docs only and does not modify #215 source. Builder atomicity (#462), persisted live-validation atomicity (#459), proposal handoff work (#209/#621), verifier/review work (#217/#220), raw JSON typing and downstream revision/revised-review stages retain their ownership.

## Safety

This is persistence-integrity acceptance only. It invokes no model, performs no target interaction, applies no code/configuration, executes no tools/remediation/retests, deploys nothing, creates no security verdict and mutates no attack path.

## Expected state

The exact #215 parser currently admits subclasses through broad `isinstance`, schema equality, tuple/list coercion, string/SHA helpers and integer checks. The new tests are intentionally expected RED only for subclasses; both exact built-in producer forms remain green.
