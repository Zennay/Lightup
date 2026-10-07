# ST5 remediation evidence-bundle mapping-key exactness

Issue: #577  
Parent: #194 exact head `ec4b09f539289fbf3b497a534980323bd3c11bef`

## Purpose

The strict persisted remediation evidence-bundle handoff must treat the identity of
mapping keys as part of the persisted schema. A key that compares equal to a
canonical field name is not canonical merely because it is a `str` subclass with
the same text, hash and equality behavior.

This acceptance slice is intentionally tests/docs only. It does not change the
#194 handoff parser or #60 producer.

## Required contract

For direct object/dict input:

- every top-level bundle key must be an exact built-in `str`;
- every remediation-item key must be an exact built-in `str`;
- every nested evidence-reference key must be an exact built-in `str`;
- canonical producer payloads with ordinary JSON-decoded keys remain accepted;
- rejection must not mutate the caller-owned payload.

The three adversarial controls replace only one canonical key object at a time:
`client_id`, `classification`, or `evidence_id`. Values, ordering and public
digests remain unchanged. Therefore an unrelated digest or lineage rejection
cannot satisfy this contract.

## Why the current parent is expected RED

At #194 head `ec4b09f539289fbf3b497a534980323bd3c11bef`, schema checks compare
`set(mapping)` to fixed key sets by value. Later reads use ordinary dict lookup
with canonical string literals. A non-exact string subclass carrying canonical
text can therefore pass schema equality and lookup without proving canonical key
identity.

The source owner should absorb this proof by validating key type before schema
equality or field access at all three mapping layers. The parser must reject
rather than normalize.

## Collision boundary

This slice does not modify:

- #194 / #60 production source or existing tests/docs;
- canonical identifier/value bounds;
- cross-item lineage uniqueness;
- path/capability identity;
- snapshot-isolation or parser input-purity owners;
- scope authorization;
- target-capable execution, remediation/retest execution or deployment;
- future-state verdict or attack-path mutation.

## Safety

This is persistence-integrity validation only. It performs no model call,
evidence collection, network/target interaction, scan, tool execution,
remediation, retest, deployment, verdict creation or attack-path mutation.
