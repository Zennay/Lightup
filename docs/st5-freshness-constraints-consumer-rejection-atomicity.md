# ST5 freshness-constraints consumer rejection atomicity

Issue: #756  
Pinned source owner: PR #131 @ `bbea958e01d3f0f83603f6b8e217255a9c19e1cc`

## Contract

The composed persisted freshness-constraints consumer must never mutate caller-owned persisted objects when validation fails.

The acceptance proof covers both rejection phases:

- strict-parser rejection after deliberate `constraints_sha256` tampering;
- live-lineage rejection after deliberate live prior-evidence SHA drift.

For both paths, repeated rejection must preserve:

- full persisted value equality;
- root and recursive dict/list object identities;
- dict key order and list order;
- deterministic fail-closed behavior across repeated calls.

## Ownership and non-overlap

This branch adds tests/docs only. PR #131 retains production consumer source ownership. #754 owns fail-fast ordering, #748 owns outer persisted runtime-type exactness, and #323/#329 retain direct parser input-purity coverage.

## Safety

Input-integrity proof only. No evidence collection, capability/tool selection, target interaction, remediation/retest execution, deployment, classification, verdict creation or attack-path mutation is introduced.

Keep this branch-only while root #62 canonical LightUp CI remains queued; do not add duplicate runner pressure.
