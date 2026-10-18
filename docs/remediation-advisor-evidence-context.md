# Remediation advisor evidence context

Issue: #845  
Parent: #843 reviewed-remediation report context

## Problem

The remediation advisor previously received only the finding title and the
current fix. The pipeline had already obtained a verifier decision and already
held the validated evidence summary, evidence references, target, severity and
impact, but none of that context reached the remediation stage.

## Contract

After the verifier has produced a valid decision, the remediation-advisor
request receives:

- finding title;
- severity and impact;
- concrete finding target;
- current fix;
- exact verifier verdict;
- validated evidence summary;
- validated evidence references.

The system instruction explicitly says that `UNCERTAIN` and `REJECTED`
decisions remain evidence-status context and must not be presented as confirmed
findings.

The pipeline preserves its order: verifier first, remediation advisor second,
report synthesizer last. Raw evidence payload bytes are never sent to the
model. Existing output fields remain unchanged.

## Safety

This change only grounds an in-memory text recommendation in evidence already
available to the review pipeline. It does not add target/network interaction,
scope or authorization, evidence collection, tool execution, remediation or
retest execution, deployment, security-verdict authority, or attack-path
mutation.
