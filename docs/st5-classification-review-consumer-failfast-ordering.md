# ST5 classification-review consumer fail-fast ordering

Issue: #340

This tests/docs-only child of exact PR #109 proves that malformed or
strict-invalid persisted classification-review input is rejected before the
live evidence-remediation lineage validator can run.

## Boundary

Base: `ad7f54c7a94467eefbc1f9ef9582ac849cb08175`.

The composed consumer has two deliberately ordered stages:

1. persisted input decoding plus strict handoff parsing;
2. live classification-review lineage validation.

The second stage must never observe input that the first stage has rejected.

## Fail-fast proof

The regression replaces the live classification-review validator with a
sentinel that raises if invoked. It then submits real-lineage consumer calls
with:

- malformed JSON text;
- duplicate JSON object keys;
- non-object JSON;
- an unsupported persisted value type;
- an exact-schema violation;
- a canonical-shape but digest-invalid request.

Each case is rejected twice by the expected persisted/strict boundary, the live
validator remains at zero calls, and the repeated error message remains
deterministic.

This pins rejection ordering independently of the input-atomicity proof in
#332/#338 and the live-lineage/StateStore read-only proof in #334.

## Safety stop line

No model is invoked and no evidence is collected. No classification or
transition is selected, and no collection, tool, target, execution,
remediation, retest, deployment or attack-path authority can be reached.
Future semantics remain unresolved and no security verdict is created.
