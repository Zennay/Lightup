# ST5 sufficiency-attestation persisted object exact types

Issue: #617  
Pinned source owner: #94 at `22207ce5f44ee3c47a19a87ce891e92e5a6099e2`

## Contract

The strict evidence-sufficiency attestation handoff parses persisted JSON-equivalent state. Direct object input must reject Python polymorphic subclasses that ordinary JSON decoding cannot produce, rather than converting equivalent-looking values into canonical enums or typed strings.

Required exact built-in runtime types:

- top-level mapping: `dict`;
- schema keys: `str`;
- candidate evidence/capability identity containers: `list`;
- identity-list entries: `str`;
- schema, identifiers, lineage digests, candidate classification claim, verifier identity, disposition, attestation digest, future semantics and verdict sentinel: `str`.

The persisted classification claim and disposition must be exact strings before enum construction. Derived sufficiency/justification/eligibility facts and all authority booleans already use identity checks and remain outside this type pack.

## Expected RED

At the pinned #94 head, broad `isinstance` checks plus schema/value equality and enum construction admit equivalent-content subclasses. The new acceptance module intentionally remains RED until #94 absorbs exact built-in type guards. Canonical `json.loads(attestation.to_json())` remains green.

## Collision boundary

This branch adds exactly one regression module and this document. It does not modify #94 source, #154 persisted-consumer/live-validation work, #323/#329 parser-purity work, #616 verifier-preflight exactness, #96/#98 classification-review work, scope authorization, or target-capable code.

## Safety

Persistence-integrity acceptance only. No disposition change, classification selection, target interaction, collection/tool execution, remediation/retest execution, deployment, security verdict, future-state resolution, or attack-path mutation.
