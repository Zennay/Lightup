# ST5 remediation typed live-object integrity pack

Issue: #792  
Downstream source-owner base: #209 `38c40d112751728c238dcf5d7ab556079528c38e`  
Composition base: #785 `1837a31469cccd8438bb1d080370e1385ded989b`

## Included contracts

1. #783 — `validate_future_remediation_authoring_request()` must accept only
   exact `FutureRemediationAuthoringRequest` runtime objects. Equality-spoofing
   subclasses, including widened-authority variants, fail closed.
2. #785 — `validate_future_remediation_text_proposal()` must accept only exact
   `FutureRemediationTextProposal` runtime objects. Producer-impossible
   subclasses, including one retaining a canonical digest while widening
   `execution_allowed`, fail closed.

## Ancestry

#209 exact head is eight commits ahead and zero behind #198 exact head, so both
contracts can be exercised on one downstream proofhead without changing either
source owner's implementation.

## Expected state before source absorption

Canonical real-producer artifacts are green controls. Polymorphic live-object
cases are intentionally RED on current source. This pack does not claim green
validation and changes no production code.

## Ownership

- #198 owns the authoring-request source guard.
- #209 owns the remediation text-proposal live-handoff guard.
- #253 retains direct-constructor invariants.
- persisted parsing, atomicity, snapshots, gateway response integrity,
  review/revision, scope authorization and target-capable lanes stay separate.

## Stop line

No target interaction, scanning, external model invocation, tool execution,
remediation/retest execution, deployment, future-state resolution, security
verdict or attack-path mutation is introduced.
