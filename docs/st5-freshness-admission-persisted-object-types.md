# ST5 freshness-admission persisted object exact types

Issue: #613  
Pinned source owner: #72 at `9bde5a0eff4daa3bc58799d16e81132ac988d7b9`

## Contract

The strict freshness-admission handoff consumes persisted JSON-equivalent data. Its direct object parser must therefore reject Python polymorphic subclasses that cannot be emitted by normal JSON decoding, even when those subclasses carry byte-for-byte canonical values.

Required exact built-in runtime types:

- top-level and candidate-evidence mappings: `dict`;
- top-level and nested schema keys: `str`;
- candidate-evidence, candidate-evidence-id and candidate-capability-id containers: `list`;
- identifiers, SHA-256 fields, schema/fixed metadata and nested evidence values: `str`;
- `current_twin_version` and `twin_version`: `int`.

Lifecycle and authority booleans already use identity checks and are not duplicated here.

## Expected RED

At the pinned #72 source head, broad `isinstance` checks plus value/schema equality admit equivalent-content subclasses. The new acceptance tests intentionally remain RED until #72 absorbs exact-type guards. The canonical control is `json.loads(admission.to_json())` and must remain green.

## Collision boundary

This branch adds exactly one regression module and this contract document. It does not modify #72 source, #141 consumer/live-validation work, #323/#329 parser-purity work, #612 freshness-constraints exactness, metadata review #78, scope authorization, or target-capable paths.

## Safety

Persistence-integrity acceptance only. No target interaction, evidence collection, capability/tool selection, classification decision, remediation/retest execution, deployment, security verdict, future-state resolution, or attack-path mutation.
