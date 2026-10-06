# ST5 remediation evidence bundle direct-construction acceptance

Issue #404 covers the typed-object boundary of the remediation-evidence bundle.

The #60 producer objects are frozen dataclasses, but immutability alone does not
make direct construction valid. Before this contract, callers can use direct
construction or `dataclasses.replace()` to create typed state that the canonical
producer and strict #194 persisted handoff would never emit.

## Acceptance surface

The regression starts from one real WORSENED producer bundle and keeps it as the
positive control. It then requires direct replacement to fail closed for
representative impossible state at all three object layers.

Evidence references cover canonical identities, exact
`future-transition-verification` kind, and canonical lowercase SHA-256 shape.

Bundle items cover remediation-only classification, canonical resolution
identity/digest shape, WORSENED current-path presence, tuple-backed/non-empty
effect/capability/evidence lineage, exact evidence-capability coverage,
canonical manifest digest shape, exact evidence-ref types, and the two required
workflow flags.

The top-level bundle covers schema/identity/SHA shape, positive exact twin
versions, exact tuple/item typing, derived count/readiness coherence, strict
bool-vs-int handling, all fail-closed authority flags, unresolved future
semantics, and a not-evaluated verdict.

## Deliberate consumer boundary

This acceptance does **not** require direct constructors to recompute full
`evidence_manifest_sha256` or `bundle_sha256` equality. Syntactically
canonical but stale/tampered digest values may remain constructible so existing
strict/live consumers can prove they reject them. Direct construction only owns
the structural state that is impossible regardless of live lineage.

## Collision boundary

Tests/docs only, based directly on exact #194 head
`ec4b09f539289fbf3b497a534980323bd3c11bef`, which contains #60 producer
source unchanged. No #60/#194 source/tests/docs or #319 snapshot-isolation
files are modified.

## Safety

Integrity narrowing only. No evidence collection, model invocation, target
interaction, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation.
