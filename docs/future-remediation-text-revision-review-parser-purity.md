# ST5 revised-remediation review parser input purity

Issue #630 proves caller-input purity above strict revised-remediation review handoff #248 at exact parent head `546716d6117918dbbb12a0720f7659b6a59ff002`.

## Invariant

The direct persisted-object parser is a read-only consumer. It must neither normalize nor mutate caller-owned state on successful parsing or on fail-closed rejection.

The proof covers both supported canonical programmatic shapes:

- `json.loads(review.to_json())`, where `checks` is an exact built-in list;
- `review.as_dict()`, where `checks` is an exact built-in tuple.

For successful parsing, the caller retains identical value content, the same root/check-container/nested-check object identities, and the same top-level and nested key ordering. Repeated parsing of the exact same object is deterministic and side-effect-free.

For failure paths, the same invariants hold after:

- a late review-digest mismatch, reached after deep field/check parsing;
- an approved-review check-coherence failure;
- an authority-widening rejection.

Repeated rejection produces the same error without accumulating mutation.

## Separation from adjacent acceptance

This is tests/docs only and does not modify #248 source.

- #627 owns producer-impossible persisted-object type exactness.
- #629 owns snapshot detachment and post-parse isolation.
- #458 owns live-validation atomicity across the upstream chain.
- #250 owns the whole revision loop remaining non-executable.
- #252 owns direct typed-object construction invariants.

## Safety

The proof uses the existing deterministic in-memory revised-review fixture and the strict parser only. It performs no external model/network call, target interaction, code/config application, tool/remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
