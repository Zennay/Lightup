# ST5 evidence-collection consumer success input atomicity

Issue #751 isolates success-path caller-input atomicity at the composed persisted
evidence-collection consumer from PR #136.

## Invariant

A valid caller-owned JSON-decoded persisted request must remain observationally
unchanged after strict parsing and immediate live-lineage validation.

The regression captures:

- the complete persisted value;
- root and recursive dict/list object identities;
- dict key ordering and list ordering.

It then consumes the exact same object twice and requires both results to equal
the canonical producer request while every persisted-input snapshot remains
unchanged.

This is intentionally a composed-consumer property. Direct #64 parser purity is
owned separately by #323/#329.

## Collision boundary

This branch is tests/docs-only and is pinned directly to PR #136 exact head
`931d71ad393df9cdfbcc3e068e65c20f3c0a7227`.

PR #136 retains source ownership. #750 owns rejection-path persisted input
atomicity; #749 owns fail-fast ordering; #747 owns outer runtime-type exactness;
#318 owns snapshot isolation.

## Safety

This is success-path input-integrity proof only. It grants no evidence
collection, capability/tool selection, target interaction, remediation/retest
execution, deployment, classification, verdict creation, or attack-path
mutation.
