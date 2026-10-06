# ST5 remediation evidence bundle resolution/effect lineage acceptance

Issue #401 preserves two locally derivable ST4 producer invariants at the
persisted #194 remediation-evidence-bundle boundary.

## Canonical producer contract

A live-validated transition resolution emits:

- a deterministic `resolution_id` shaped exactly as
  `transition-resolution:<24 lowercase hex>`;
- non-empty `effect_ids`;
- canonical identifiers with no leading/trailing whitespace, no control
  characters, and a maximum length of 256 characters.

The #60 bundle producer copies that already validated lineage. The persisted
handoff must not admit shapes the producer cannot emit merely because a caller
can recompute the public bundle digest.

## Acceptance

A real WORSENED producer bundle is the positive control.

The negative cases independently recompute a matching `bundle_sha256` after:

- wrong resolution-ID prefix;
- wrong resolution-ID suffix length;
- uppercase resolution-ID hex;
- erasing all `effect_ids`;
- using whitespace-padded, control-character, or overlong effect identifiers.

Strict parsing must fail closed rather than trimming, normalizing, or accepting
the impossible producer state.

## Collision boundary

Tests/docs only, based directly on active #194. No #194 source/tests/docs are
modified.

This is downstream and distinct from #396 at the remediation/retest-plan
handoff, plus bundle-specific #398/#399/#400 and #319.

## Safety

Persistence-integrity acceptance only. No evidence collection, target
interaction, tool execution, remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
