# Persisted evidence-freshness coverage consumer

This ST5 evidence-remediation boundary composes two existing guarantees into one
consumer API:

1. strict persisted freshness-coverage parsing; and
2. immediate live rebuilding against the current StateStore and complete
   request/constraints/admission/context lineage.

Consumers should use
`load_and_validate_future_security_evidence_freshness_coverage` when loading
persisted JSON or object payloads. A successful return means the payload is both
serialization-valid and still equal to the current live-validated coverage.

## Duplicate-key fail-closed rule

JSON text is decoded with duplicate-object-key rejection. This prevents ordinary
JSON last-key-wins behavior from normalizing an ambiguous payload before the
strict coverage schema sees it. The duplicate-key guard applies recursively to
nested objects through the JSON decoder hook.

Object inputs still pass through the existing exact-schema parser, including
canonical identifiers and SHA-256 values, canonical item ordering, derived
count checks, fixed false safety flags and recomputed coverage digest.

## Live validity is mandatory

After strict parsing, the consumer immediately calls the existing live coverage
validator. Drift in evidence ledger state, admissions, candidate run contexts,
freshness constraints or older request/remediation lineage therefore fails
closed before a caller receives the coverage object.

Complete freshness coverage remains only a freshness fact. It does not evaluate
sufficiency, close a gap, select a classification, create a transition
resolution, authorize collection/tool/target execution, author remediation,
authorize future-state retests, deploy, or mutate attack paths.

This boundary performs no target interaction and introduces no new execution
authority.
