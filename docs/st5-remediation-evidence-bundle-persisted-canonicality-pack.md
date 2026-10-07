# ST5 remediation evidence-bundle persisted canonicality pack

Tracking issue: #712  
Source owner: #194  
Exact source parent: `ec4b09f539289fbf3b497a534980323bd3c11bef`  
Base composition: `chatgpt/st5-remediation-evidence-bundle-persisted-type-pack-20261007`  
Mode: composition-only tests/docs acceptance

## Included contracts

This branch preserves the existing persisted type-fidelity pack:

- #577 — exact built-in schema-key strings;
- #578 — exact built-in mapping/list containers;
- #579 — exact built-in fixed metadata/classification strings;
- #580 — exact built-in SHA-256 strings;
- #581 — exact built-in count integers;
- #582 — exact built-in raw JSON text;
- #663 — exact built-in remaining lineage/evidence strings.

It additionally composes:

- #666 — canonical lexical ordering of persisted `effect_ids`, including a
  recomputed outer `bundle_sha256` so stale-digest rejection cannot mask the
  ordering invariant.

The canonical producer round-trip remains the green control. The reordered
effect case is an acceptance RED until the #194 source owner absorbs the
minimal ordering guard.

## Ownership boundary

This pack changes no production source and does not take over #194. It also
does not absorb capability/current-path ordering, resolution/effect identifier
content semantics, direct-construction, snapshot isolation, parser purity,
live-validation atomicity, scope authorization, model/gateway, or target-capable
work.

## Promotion use

Keep this branch PR-less while the permanent self-hosted LightUp queue is
occupied and the newly composed #666 case is expected RED. After #194 absorbs
the guard, restack/reprove this exact composition and require both canonical
producer controls and the full persisted canonicality set to be green before
promotion.

## Safety

Persistence-integrity validation only. No model invocation, evidence
collection, target interaction, scanning, tool/remediation/retest execution,
deployment, security-verdict creation, or attack-path mutation.
