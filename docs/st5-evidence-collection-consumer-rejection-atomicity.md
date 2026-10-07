# ST5 evidence-collection consumer rejection input atomicity

Issue #750 isolates caller-input atomicity at the composed persisted
evidence-collection consumer from PR #136.

## Invariant

A caller-owned JSON-decoded persisted request must remain observationally
unchanged when the consumer fails closed, regardless of whether rejection occurs
during strict parsing or during immediate live-lineage validation.

The regression captures, after the deliberate test tamper:

- the complete persisted value;
- root and recursive dict/list object identities;
- dict key ordering and list ordering.

It then proves the same object can be rejected repeatedly without any mutation
or accumulated normalization.

Two stages are covered:

1. strict request-digest rejection before live validation; and
2. live-lineage rejection after strict parsing by deleting the prior evidence
   that the canonical request depends on.

## Collision boundary

This branch is tests/docs-only and is pinned directly to PR #136 exact head
`931d71ad393df9cdfbcc3e068e65c20f3c0a7227`.

PR #136 retains consumer source ownership. #749 owns fail-fast ordering; #747
owns outer persisted runtime-type exactness; #611/#746 own direct #64 parser
exactness; #323/#329 own direct parser input purity; #318 owns snapshot
isolation.

## Safety

This is input-integrity proof only. It grants no evidence collection,
capability/tool selection, target interaction, remediation/retest execution,
deployment, classification, verdict creation, or attack-path mutation.
