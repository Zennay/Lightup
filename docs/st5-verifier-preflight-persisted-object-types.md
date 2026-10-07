# ST5 sufficiency verifier-preflight persisted object exact types

Issue: #616  
Pinned source owner: #91 at `8c87b83ae12628d279e89e166a96a5659fcf19a7`

## Contract

The strict verifier-preflight handoff consumes persisted JSON-equivalent state. Direct-object parsing must reject Python polymorphic subclasses that canonical JSON decoding cannot produce, even when those values compare equal to the expected persisted state.

Required exact built-in runtime types:

- top-level mapping: `dict`;
- schema keys: `str`;
- candidate evidence/capability identity containers: `list`;
- identity-list entries: `str`;
- schema, identifiers, lineage digests, classification claim, verifier identity, `verifier_role`, future semantics and verdict sentinel: `str`.

The verifier role is especially important: only an exact built-in `"operator"` value may cross the persisted boundary before the parser constructs the canonical typed role value. Existing lifecycle/authority booleans already use identity checks.

## Expected RED

At the pinned #91 head, broad `isinstance` checks and value/schema equality admit equivalent-content subclasses. These acceptance tests intentionally remain RED until #91 absorbs exact built-in type guards. The canonical control is `json.loads(preflight.to_json())` and stays green.

## Collision boundary

This branch adds one regression module and this document only. It does not modify #91 source, #150 persisted-consumer/live-validation work, #323/#329 parser-purity work, #615 sufficiency-request exactness, attestation/downstream work, scope authorization, or target-capable code.

## Safety

Persistence-integrity acceptance only. No evidence decision, classification, target interaction, collection/tool execution, remediation/retest execution, deployment, security verdict, future-state resolution, or attack-path mutation.
