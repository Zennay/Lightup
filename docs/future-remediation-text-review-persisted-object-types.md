# ST5 remediation-text review persisted object type exactness

Issue #623 isolates a persistence-type boundary above strict remediation-text review handoff #220 at exact parent head `82126cfccdcef85f51cd5d34cdcccfb05ebe8270`.

## Contract

The canonical direct-object control is `json.loads(review.to_json())`. Persisted JSON decoding yields exact built-in dictionaries, lists and strings. The direct `future_remediation_text_review_from_dict` path must reject equivalent-content Python subclasses rather than normalize them into trusted review state.

The acceptance regression requires exact built-in types for:

- the top-level mapping and all top-level schema keys;
- the `checks` sequence container;
- every nested check mapping and nested schema key;
- review-request/proposal/content/review SHA-256 lineage;
- reviewer provider/model provenance;
- schema/future/verdict metadata;
- persisted decision, check-name and check-result strings;
- the review summary, before trimming/canonicalization.

Canonical JSON-decoded producer state must continue to reconstruct the exact review. Rejection must leave caller-owned persisted input value-equivalent to its pre-call snapshot.

## Separation from existing owners

This branch adds tests/docs only and does not modify #220 source. Reviewer producer atomicity (#465), persisted live-validation atomicity (#454), model/summary canonicality (#434/#442), review-request #215/#622, raw JSON typing and downstream revision/revised-review work keep their scopes.

## Safety

This is persistence-integrity acceptance only. It invokes no model, interacts with no target, applies no code/configuration, executes no tools/remediation/retests, deploys nothing, creates no security verdict and mutates no attack path.

## Expected state

The exact #220 parser currently uses broad `isinstance`, schema/value equality, enum conversion, nested traversal and summary `.strip()` canonicalization at these boundaries. The new tests are intentionally expected RED until the #220 source owner narrows the persisted-object contract.
