# ST5 metadata-review persisted object exact types

Issue: #614  
Pinned source owner: #81 at `8e74bff8783fcc7019be350a6549b824d7f2e1af`

## Contract

The strict metadata-contract review handoff parses persisted JSON-equivalent data. Direct object input must not accept polymorphic Python subclasses that JSON decoding cannot produce, even when they compare equal to canonical values.

Required exact built-in runtime types:

- top-level mapping: `dict`;
- schema keys: `str`;
- candidate evidence/capability identity containers: `list`;
- identity-list entries: `str`;
- identifiers, lineage/review SHA-256 values, schema/fixed metadata and candidate classification claim: `str`;
- current/future twin versions: `int`.

The existing positive/negative lifecycle and authority booleans already use identity checks and are outside this pack.

## Expected RED

At the pinned #81 head, broad `isinstance` checks, schema/value equality and enum construction admit equivalent-content subclasses. The new acceptance module is intentionally RED until #81 absorbs exact built-in type guards. The canonical JSON-decoded review remains the green control.

## Collision boundary

This branch adds exactly one regression module and this document. It does not modify #81 source, #145 persisted-consumer/live-validation work, #323/#329 parser-purity work, #613 freshness-admission exactness, downstream sufficiency-review work, scope authorization, or target-capable code.

## Safety

Persistence-integrity acceptance only. No target interaction, evidence collection, capability/tool selection, sufficiency/classification decision, remediation/retest execution, deployment, security verdict, future-state resolution, or attack-path mutation.
