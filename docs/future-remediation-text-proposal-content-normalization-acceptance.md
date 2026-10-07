# ST5 remediation text proposal canonical-content acceptance

This tests/docs-only acceptance contract sits directly above exact active #209
strict remediation text proposal handoff head
`38c40d112751728c238dcf5d7ab556079528c38e`.

## Producer invariant

The exact #207 proposal producer validates non-empty model output and then
canonicalizes it before hashing and persistence:

`content = response.content.strip()`

Both `content_sha256` and `proposal_sha256` are therefore computed over an
already-trimmed string. Leading or trailing whitespace is not producer-reachable
proposal state.

## Persisted gap

The #209 parser checks only that `content.strip()` is non-empty. It returns the
original caller string unchanged, then validates digests over that unchanged
value.

A persisted caller can therefore add outer whitespace, recompute
`content_sha256` and `proposal_sha256`, and reconstruct typed proposal state
the canonical #207 producer cannot emit.

## Acceptance

The regression contract requires:

1. an untouched real producer proposal still round-trips;
2. leading-space content fails closed;
3. trailing-space content fails closed;
4. outer-tab content fails closed;
5. every forged case carries a recomputed matching content digest and proposal
   digest;
6. persisted input is rejected rather than silently stripped or normalized.

This is deliberately separate from #427/#428, which owns only the
gateway-normalized `model_id` invariant.

## Collision boundary

Issue #439 adds only this regression module and this contract document. It does
not modify #209/#207 source/tests/docs or #427/#428 files and does not take
source ownership.

No model invocation, code/config generation, target interaction, tool execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation is introduced.

## Expected state

Until #209's source owner absorbs the narrow content canonicalization invariant,
the canonical producer control should stay green while the three outer-
whitespace cases are expected RED. After absorption, the target is **3 RED → 0
RED** while the parent handoff and safety canaries remain green.
