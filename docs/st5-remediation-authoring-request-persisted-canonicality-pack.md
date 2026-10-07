# ST5 remediation authoring-request persisted canonicality pack

Tracking issue: #713  
Source owner: #198  
Exact source parent: `7f41af2dcbecd84eee7830cae8b05c6acecdb923`  
Base composition: `chatgpt/st5-remediation-authoring-request-persisted-type-pack-20261007`  
Mode: composition-only tests/docs acceptance

## Included contracts

This branch preserves the existing persisted runtime type-fidelity pack:

- #583 — exact built-in raw JSON text;
- #628 — exact built-in mappings, lists and schema-key strings;
- #658 — exact built-in persisted non-boolean scalar values.

It additionally composes:

- #668 — canonical lexical ordering of persisted `effect_ids`, with
  `request_sha256` recomputed so stale-digest rejection cannot mask the
  ordering invariant.

The canonical producer request is the green control. The reordered effect case
is acceptance RED until the #198 source owner absorbs the minimal ordering
guard.

## Ownership boundary

This pack changes no production source and does not take over #198. Canonical
identifier content, path/capability semantics, evidence-kind, cross-item
lineage, direct construction, snapshot isolation, parser purity,
producer/live-validation atomicity, implementation planning, scope
authorization and target-capable work remain with their existing owners.

## Promotion use

Keep this branch PR-less while the permanent self-hosted LightUp queue is
occupied and #668 remains expected RED. After #198 absorbs the ordering guard,
restack/reprove this exact composition and require the canonical producer plus
the complete persisted canonicality set to be green before promotion.

## Safety

Persistence-integrity validation only. No model invocation, evidence
collection, target interaction, scanning, code/config generation,
tool/remediation/retest execution, deployment, security-verdict creation or
attack-path mutation.
