# ST5 remediation evidence-bundle JSON text exactness

Issue: #582  
Parent: #194 exact head `ec4b09f539289fbf3b497a534980323bd3c11bef`

## Purpose

The strict remediation evidence-bundle handoff accepts persisted raw JSON text
as well as a direct Python object. Real JSON persistence supplies an exact
built-in `str`; a direct caller can instead provide a `str` subclass.

The persistence boundary should not widen the raw-text input model through
polymorphic text objects before duplicate-key-safe JSON decoding.

## Required contract

- canonical producer JSON must be an exact built-in `str` and remain valid;
- a `str` subclass carrying byte-for-byte canonical JSON must be rejected
  before JSON decoding;
- the caller-visible object must not be normalized, rewritten, or coerced.

This is an input-boundary contract only. It does not claim the persisted field
type slices owned by #579/#580, mapping/container slices #577/#578, derived
integer slice #581, or existing path/capability/evidence-kind/lineage work.

## Why the current parent is expected RED

At #194 head `ec4b09f539289fbf3b497a534980323bd3c11bef`,
`future_remediation_evidence_bundle_from_json()` checks
`isinstance(raw, str)`. A `str` subclass containing canonical JSON therefore
passes that guard and is decoded as if it were the exact persistence type.

The source owner should absorb this contract with an exact built-in type check
before truthiness inspection or JSON decoding. Rejection is preferred over
coercion so no polymorphic caller object is silently normalized.

## Collision boundary

This acceptance slice adds one regression module and this contract document.
It changes no production/source file, no existing test/doc, and does not touch:

- #194 source ownership;
- #577-#581 acceptance ownership;
- remediation authoring, implementation-plan or revised-plan source;
- scope authorization;
- execution, target interaction, remediation/retest execution or deployment;
- future-state resolution, verdict creation or attack-path mutation.

## Safety

Persistence-integrity validation only. No model call, network I/O, target
interaction, scan, tool execution, remediation, retest, deployment, verdict
creation or attack-path mutation.
