# ST5 sufficiency-review request persisted object exact types

Issue: #615  
Pinned source owner: #86 at `ef1496b53330926aadec9901fc5805d9a4b6363a`

## Contract

The strict evidence-sufficiency review-request handoff accepts persisted JSON-equivalent data. Direct object input must reject Python subclasses that ordinary JSON decoding cannot emit, rather than normalizing equivalent-looking polymorphic values into trusted typed state.

Required exact built-in runtime types:

- top-level mapping: `dict`;
- schema keys: `str`;
- candidate evidence/capability identity and `required_checks` containers: `list`;
- entries in those lists: `str`;
- identifiers, SHA-256 lineage, schema/fixed metadata and candidate classification claim: `str`;
- current/future twin versions: `int`.

The fixed review rubric is compared by value today and then replaced with the canonical tuple. This contract additionally requires the persisted list and its entries themselves to be canonical built-ins before that replacement.

## Expected RED

At the pinned #86 source head, broad `isinstance` checks plus set/value equality and enum construction admit equivalent-content subclasses. The new acceptance module is intentionally RED until #86 absorbs exact built-in type guards. `json.loads(request.to_json())` remains the canonical green control.

## Collision boundary

This branch adds one regression module and this document only. It does not modify #86 source, #148 persisted-consumer/live-validation work, #323/#329 parser-purity work, #614 metadata-review exactness, verifier-preflight/downstream work, scope authorization, or target-capable code.

## Safety

Persistence-integrity acceptance only. No target interaction, evidence collection, capability/tool selection, sufficiency/classification decision, remediation/retest execution, deployment, security verdict, future-state resolution, or attack-path mutation.
