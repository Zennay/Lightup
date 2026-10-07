# ST5 freshness-constraints consumer fail-fast ordering

Issue: #754  
Pinned source owner: PR #131 @ `bbea958e01d3f0f83603f6b8e217255a9c19e1cc`

## Contract

The persisted freshness-constraints consumer must complete every persisted-input and strict-parser rejection before the live lineage validator is invoked.

The acceptance test uses the real #131 producer fixture and replaces the live validator with a fail-fast sentinel. It covers:

- malformed JSON text;
- duplicate object keys;
- non-object JSON;
- unsupported persisted runtime type;
- exact-schema rejection;
- digest rejection after successful JSON/object decoding.

Every case must raise `ValueError` while the live validator call count remains zero.

## Why this matters

The composed boundary is ordered deliberately:

1. decode persisted input with duplicate-key rejection;
2. require a JSON object;
3. run the exact #68 strict parser;
4. only then perform live request/plan/report/preview/proposal/resolution/context/StateStore validation.

This prevents malformed or integrity-invalid durable state from reaching the live validation layer and keeps the consumer's trust boundary explicit.

## Ownership and non-overlap

This branch adds tests/docs only. PR #131 retains production consumer ownership. #748 owns outer persisted runtime-type subclass rejection, #612 owns direct #68 parser exactness, and #323/#329 retain parser input-purity coverage.

## Safety

Persistence-validation ordering only. No evidence collection, capability/tool selection, target interaction, remediation/retest execution, deployment, classification, verdict creation or attack-path mutation is introduced.

Keep this branch-only while root #62 canonical LightUp CI remains queued; do not create duplicate runner pressure.
