# ST5 remediation text-proposal live object identity

Issue: #785  
Pinned parent: #209 exact head `38c40d112751728c238dcf5d7ab556079528c38e`

## Boundary

`validate_future_remediation_text_proposal()` accepts a typed proposal after
revalidating its authoring lineage and recomputing content/proposal digests.
Canonical production emits an exact frozen `FutureRemediationTextProposal`.

The live consumer currently uses a broad `isinstance` gate. That admits
producer-impossible subclasses. This matters independently of persisted parsing
and direct-constructor hardening because the validator returns the caller object
after validation.

## Acceptance contract

The regression module requires:

- an exact real-producer proposal remains accepted and is returned unchanged;
- a subclass with otherwise canonical fields fails closed at the live boundary;
- a subclass carrying `execution_allowed=True` also fails closed even when it
  retains the canonical producer `proposal_sha256`;
- repeated rejection leaves the caller-owned typed object unchanged.

The source-owner repair is deliberately narrow: require
`type(proposal) is FutureRemediationTextProposal` before live lineage or
digest processing.

## Why the authority case is relevant

The proposal digest helper serializes the canonical safe lifecycle/authority
values rather than reading those authority fields from the supplied typed
object. Exact runtime identity therefore belongs at the live typed-artifact
boundary even when direct-constructor invariants are hardened separately.

## Non-overlap

This child is tests/docs only. Production ownership remains with #207/#209, and
#253 retains direct-constructor ownership. It is separate from #452 atomicity,
#621 persisted object exactness, #636 snapshot isolation, #641 parser purity,
#584 raw JSON typing, #427/#439 producer canonicality, and downstream review
work.

## Safety

Validation-integrity only. No external model call, target/network interaction,
evidence collection, tool execution, remediation/retest execution, deployment,
future-state resolution, verdict creation, or attack-path mutation.
