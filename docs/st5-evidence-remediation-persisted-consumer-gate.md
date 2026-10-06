# ST5 persisted evidence-remediation consumer gate

This gate defines the final persistence-integrity contract for the ST5
evidence-remediation chain before any classification review may begin.

It is intentionally **PLAN-LAB ONLY**. It does not select a security
classification, create a transition resolution, authorize collection or
execution, interact with targets, author remediation, run a future-state
retest, deploy, or mutate attack paths.

## Non-bypassable persisted-consumer invariant

Every persisted evidence-remediation artifact must be consumed through the
same three-stage boundary:

1. **Duplicate-key-safe JSON decode** when the persisted input is JSON text.
   Ambiguous JSON must fail before ordinary last-key-wins normalization can
   choose a value.
2. **Exact strict parser** for the artifact. Schema, primitive types,
   canonical identifiers/digests, ordering, counts, derived flags and
   fail-closed semantics must be rechecked.
3. **Immediate live validator** against the current StateStore and the complete
   upstream lineage required by that artifact.

A caller must not receive a parsed object from the composed consumer unless
all applicable stages pass. Direct use of a strict parser is serialization
integrity only and is not sufficient for downstream trust.

## Covered boundaries

| Persisted boundary | Strict handoff | Composed consumer | Hosted exact-head proof | Canonical VPS gate |
| --- | --- | --- | --- | --- |
| Evidence collection request | #64 | #136 | `931d71ad393df9cdfbcc3e068e65c20f3c0a7227` / run `37440566889` success | run `37440566874` |
| Freshness constraints | #68 | #131 | `bbea958e01d3f0f83603f6b8e217255a9c19e1cc` / run `37440057143` success | run `37440057067` |
| Freshness admission | #72 | #141 | `cfa22936bb2e3fc95665a0a032143d708a4568fe` / run `37440784944` success | run `37440785044` |
| Freshness coverage | #77 + chain proof #110 | #128 | `fd5f9c39ae2f1d268b72359b904dc93b1e5e4a57` / run `37439757888` success | run `37439757870` |
| Metadata-contract review | #81 | #145 | `e2a64382a55289a45cf74aedf6e0f65f04126e04` / run `37441060790` success | run `37441060792` |
| Sufficiency-review request | #86 | #148 | `bc679013a2986bfc949d40e279790862d64dd1b0` / run `37442038813` success | run `37442038763` |
| Sufficiency verifier preflight | #91 | #150 | `05fa52659f7b7d44bc87d737429d6e719e9a769a` / run `37442042948` success | run `37442043320` |
| Sufficiency attestation | #94 | #154 | `e4c82fe0d311548b3d59e1f4c744a88e114f4b13` / run `37441644669` success | run `37441644595` |
| Classification-review request | #98 | #109 | `ad7f54c7a94467eefbc1f9ef9582ac849cb08175` / run `37433397492` success | run `37433397632` |

Hosted proof is necessary but not sufficient for promotion. The canonical
self-hosted VPS run must also be green for the same exact head after the
relevant parent chain has landed or been restacked.

## Merge-order gate

Consumer packages are intentionally stacked on the exact strict-handoff heads
they harden. For each row above:

1. land and re-prove the parent dependency chain first;
2. restack the strict handoff if its parent moved;
3. restack the composed consumer on the resulting exact strict-handoff head;
4. require fresh hosted Python 3.11/3.14 proof;
5. require fresh canonical self-hosted VPS proof for that exact head;
6. keep the consumer draft until both proof classes are green;
7. only then allow downstream evidence-remediation stages to rely on that
   persisted boundary.

A green later-stage package does not waive an unproven earlier-stage consumer.

## Authority-widening audit

The composed-consumer PR diffs were audited together (#109, #128, #131, #136,
#141, #145, #148, #150 and #154). Across their added lines there are no
positive assignments that widen any of these authorities:

- classification selection;
- transition-resolution creation;
- evidence collection authorization;
- tool-call creation;
- execution;
- target interaction;
- remediation authoring;
- future-state retest;
- deployment;
- attack-path mutation.

This is an additional integration check, not a substitute for the exact parser,
live validator, hosted proof, canonical VPS proof or dependency/restack gates.

## Semantic stop line

The evidence-remediation chain ends at the validated
classification-review **request**. That request may establish only that a
later classification review is required. This gate does not perform that
review.

At this stop line:

- `classification_selected=false`;
- `transition_resolution_created=false`;
- collection/tool/target execution authority remains false;
- remediation and future-state retest authority remain false;
- deployment and attack-path mutation authority remain false;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

Any future package that crosses this stop line must be reviewed as a separate
classification-decision phase rather than being smuggled into
evidence-remediation persistence handling.

Refs #158.
