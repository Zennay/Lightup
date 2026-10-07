# ST5 freshness-coverage persisted object exact types

Issue: #619  
Pinned source owner: #77 at `629893d8dd10ab4dedda6b23f1b4230ddba3b67d`

## Contract

The strict freshness-coverage handoff consumes persisted JSON-equivalent state. Direct object input must reject Python subclasses that normal JSON decoding cannot produce, even when those values compare equal to canonical data.

Required exact built-in runtime types:

- top-level and coverage-item mappings: `dict`;
- top-level and item schema keys: `str`;
- `items` and candidate-evidence identity containers: `list`;
- candidate-evidence identity entries: `str`;
- schema, identifiers, digest lineage, covered-item admission/run identity, future semantics and verdict sentinel: `str`;
- twin versions and derived coverage counts: `int`.

Both covered and uncovered canonical JSON controls remain valid. Existing boolean coverage/authority fields keep their current exact boolean checks; uncovered admission/run sentinels remain `None`.

## Expected RED

At the pinned #77 head, broad `isinstance` checks plus schema/value equality admit equivalent-content mapping/list/string/integer subclasses. This acceptance module intentionally remains RED until #77 absorbs exact built-in type guards. Canonical `json.loads(coverage.to_json())` remains green.

## Collision boundary

This branch adds one regression module and this document only. It does not modify #77 source, #110 integration proof, #128 persisted-consumer/live-validation work, #323/#329 parser-purity work, #612/#613 exactness siblings, scope authorization, or target-capable code.

## Safety

Persistence-integrity acceptance only. Freshness coverage is neither evidence sufficiency nor gap closure. No classification, target interaction, collection/tool execution, remediation/retest execution, deployment, security verdict, future-state resolution, or attack-path mutation is introduced.
