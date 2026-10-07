# ST5 remediation-text review persisted object type exactness

Issue #623 isolates a persistence-type boundary above strict remediation-text review handoff #220 at exact parent head `82126cfccdcef85f51cd5d34cdcccfb05ebe8270`.

## Contract

Both built-in producer forms already exercised by the strict handoff must remain green:

- `json.loads(review.to_json())`, where `checks` is an exact built-in list;
- `review.as_dict()`, where the dataclass preserves `checks` as an exact built-in tuple.

The direct `future_remediation_text_review_from_dict` path must reject equivalent-content Python subclasses rather than normalize them into trusted review state.

The acceptance regression covers:

- the top-level mapping and all top-level schema keys;
- both supported `checks` container types;
- every nested check mapping and nested schema key;
- review-request/proposal/content/review SHA-256 lineage;
- reviewer provider/model provenance;
- schema/future/verdict metadata;
- persisted decision, check-name and check-result strings;
- the review summary before trimming/canonicalization.

Rejection must leave caller-owned persisted input value-equivalent to its pre-call snapshot.

## Separation from existing owners

This branch adds tests/docs only and does not modify #220 source. Reviewer producer atomicity (#465), persisted live-validation atomicity (#454), model/summary canonicality (#434/#442), review-request #215/#622, raw JSON typing and downstream revision/revised-review work keep their scopes.

## Safety

This is persistence-integrity acceptance only. It invokes no model, interacts with no target, applies no code/configuration, executes no tools/remediation/retests, deploys nothing, creates no security verdict and mutates no attack path.

## Expected state

The exact #220 parser currently uses broad `isinstance`, schema/value equality, enum conversion, list/tuple and nested-mapping checks, plus summary `.strip()` canonicalization. The new tests are intentionally expected RED only for producer-impossible subclasses while both supported built-in forms stay green.
