# Finding evidence decode-failure contract

Issue #886 is a tests/docs-only decoder-edge sidecar for #856.

## Gap

The primary #856 acceptance branch covers malformed but syntactically valid JSON
shapes. Durable SQLite drift can also contain invalid JSON text or valid JSON
scalars that are not evidence-reference arrays.

Those inputs must not leak parser-specific exceptions such as
`json.JSONDecodeError` or `TypeError` through the domain API. The durable
finding read boundary should present the same deterministic evidence-integrity
`ValueError` for every malformed persisted evidence shape.

## Required behavior

The regression covers:

- syntactically invalid JSON;
- JSON `null`;
- a numeric JSON scalar.

Each case must fail closed with an evidence-identifying `ValueError` and leave
the persisted `evidence_ids_json` value unchanged.

## Non-overlap

No production source is changed. #828 retains finding-read query ownership and
#856 retains the future decoder source successor. #857 write-side finding
evidence, #854 labsync, Security Twin projection, target-capable code,
deployment and verdict logic remain untouched.

## Safety

Temporary-SQLite read-integrity proof only. No target/network interaction,
evidence collection, remediation/retest execution or deployment.
