# ST5 remediation authoring-request canonical evidence-kind acceptance

Issue: #411

This tests/docs-only slice is based on exact active #198 head `7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

## Contract

The live lineage only emits evidence references with `kind="future-transition-verification"`. ST4 enforces that value, #60 carries it into the remediation evidence bundle, and #196 copies it unchanged into the authoring request.

The #198 persisted parser currently accepts any non-empty `kind`. This acceptance proves that a caller cannot substitute a different non-empty kind, recompute both the evidence-manifest and request digests, and still reconstruct producer-impossible typed state.

The control uses a real WORSENED producer request. The forged case calls the strict parser directly so a later live-lineage mismatch cannot satisfy the test accidentally.

## Boundary

Exactly one new regression module and one document. No #198/#196/#60 source, existing tests/docs, model gateway, scope authorization, execution, target, remediation/retest, deployment, verdict or attack-path mutation code is modified.

## Expected state

The canonical producer control is green. The alternative-kind assertion is expected RED until #198 absorbs the exact-kind check.

## Safety

Persistence-integrity proof only. No model invocation, code/config generation, target interaction, tool execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
