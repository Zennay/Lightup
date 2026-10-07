# ST5 remediation evidence-bundle count scalar exactness

Issue: #581  
Parent: #194 exact head `ec4b09f539289fbf3b497a534980323bd3c11bef`

## Purpose

The strict persisted remediation evidence-bundle handoff accepts direct Python
objects as well as JSON. JSON-decoded count values are exact built-in integers,
while direct callers can provide `int` subclasses. The strict object boundary
must not widen the persisted scalar model through integer polymorphism.

## Required contract

Require exact built-in `int` values for:

- `remediation_item_count`;
- `blocking_evidence_gap_count`.

The canonical producer payload remains the green control. Each adversarial case
retains the exact canonical numeric value and all public digest equality; only
the runtime scalar type changes. Rejection must not mutate caller input.

## Expected RED at the current parent

At #194 head `ec4b09f539289fbf3b497a534980323bd3c11bef`,
`_non_negative_int` accepts any `isinstance(value, int)` value except bool.
Therefore ordinary non-bool integer subclasses cross this direct-object
boundary.

The source owner should require `type(value) is int` for these derived count
fields before range/coherence checks. Do not coerce.

## Collision boundary

#398 already owns twin-version positivity and remains untouched. #404 owns
direct typed-object construction. This slice is also distinct from #577
mapping-key identity, #578 container identity, #579 fixed strings and #580
digest strings. It changes no #194/#60 production source or existing tests/docs.

## Safety

Persistence-integrity validation only. No model call, evidence collection,
network or target interaction, scanning, execution, remediation, retest or
deployment.
