# ST5 evidence-remediation parser rejection purity

Issue: #329

This contract complements the successful-input parser-purity gate in #323/#324.
It proves that strict persisted evidence-remediation parsers also leave caller-owned
JSON objects untouched when parsing fails.

## Boundary

The regression is stacked on exact PR #98 head
`1369e04a33d55a91479d434208cc6064ac55809d` and covers the persisted
boundaries already present in that ancestry:

- evidence collection request;
- freshness constraints;
- freshness admission;
- evidence-sufficiency attestation;
- classification-review request.

It adds no producer/parser/consumer implementation and does not modify the
#323/#324 purity files.

## Rejection cases

Each real producer artifact is serialized and decoded into a caller-owned
dictionary. The test then proves two distinct rejection paths:

1. an unexpected top-level key exercises exact-schema rejection;
2. canonical-shape SHA-256 values are changed without changing their type,
   length, or lowercase-hex shape, forcing integrity/digest rejection beyond
   the shallow schema check.

Before each parser call, the already-tampered caller object is snapshotted by
value, JSON ordering, and recursive dict/list object identity. The same object
is rejected twice. After every rejection all three views must remain exactly
unchanged.

A strict parser therefore cannot sort, pop, normalize, replace, or otherwise
rewrite caller-owned containers as a side effect of failing closed.

## Safety stop line

This is an in-memory persistence-integrity proof only. It does not collect
evidence, invoke a model, select a classification, resolve a transition, create
tool calls, interact with a target, execute remediation or retest actions,
authorize deployment, resolve future semantics, create a security verdict, or
mutate attack paths.
