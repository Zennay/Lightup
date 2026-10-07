# ST5 remediation authoring-request JSON text exactness

Issue: #583  
Parent: #198 exact head `7f41af2dcbecd84eee7830cae8b05c6acecdb923`

## Purpose

The strict remediation authoring-request handoff accepts persisted raw JSON
text as well as a direct Python object. Real serialization supplies an exact
built-in `str`; direct Python callers can provide subclasses instead.

The raw persistence boundary must stay exact before duplicate-key-safe JSON
decoding, rather than silently widening to polymorphic text objects.

## Required contract

- canonical producer JSON is an exact built-in `str` and remains valid;
- a `str` subclass with byte-for-byte canonical JSON text is rejected before
  JSON decoding;
- caller input is not coerced, normalized, or rewritten.

This slice owns only raw JSON input identity. It does not claim #198 source,
#450 live-validation atomicity, #469 producer atomicity, existing field/path/
capability/evidence-kind/lineage ownership, or #582's earlier evidence-bundle
JSON boundary.

## Why the current parent is expected RED

At #198 head `7f41af2dcbecd84eee7830cae8b05c6acecdb923`,
`future_remediation_authoring_request_from_json()` checks
`isinstance(raw, str)`. Canonical content carried by a `str` subclass
therefore reaches `json.loads()` and is accepted as if it were the exact
persisted text type.

The source owner should absorb this proof with an exact built-in type check
before truthiness inspection or JSON decoding. Reject rather than coerce.

## Collision boundary

This branch adds one regression module and this contract document only.
It does not modify production/source, existing tests/docs, scope authorization,
or target-capable behavior.

## Safety

Persistence-integrity validation only. No model call, network I/O, target
interaction, scan, tool execution, remediation, retest, deployment,
future-state resolution, verdict creation or attack-path mutation.
