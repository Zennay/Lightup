# ST5 classification-review request persisted object exact types

Issue: #618  
Pinned source owner: #98 at `1369e04a33d55a91479d434208cc6064ac55809d`

## Contract

The strict classification-review request handoff is a persisted evidence-remediation boundary. Direct object input must accept only runtime types ordinary JSON decoding can produce, rejecting Python subclasses even when they compare equal to canonical data.

Required exact built-in runtime types:

- top-level mapping: `dict`;
- schema keys: `str`;
- candidate evidence/capability identity containers: `list`;
- identity-list entries: `str`;
- schema, identifiers, complete digest lineage, candidate classification claim, verifier identity, future semantics and verdict sentinel: `str`.

The candidate classification remains only the evidence claim under review. Its persisted value must be an exact built-in string before enum conversion. Existing review-eligibility and action-authority booleans already use identity checks.

## Expected RED

At the pinned #98 head, broad `isinstance` checks plus schema/value equality and enum construction admit equivalent-content subclasses. This acceptance module intentionally remains RED until #98 absorbs exact built-in type guards. Canonical `json.loads(request.to_json())` remains green.

## Collision boundary

This branch adds exactly one regression module and this document. It does not modify #98 source, #109 persisted-consumer/live-validation work, #323/#329 parser-purity work, #617 attestation exactness, classification-reviewer/decision work, scope authorization, or target-capable code.

## Safety

Persistence-integrity acceptance only. No classification decision, transition resolution, target interaction, collection/tool execution, remediation/retest execution, deployment, security verdict, future-state resolution, or attack-path mutation.
