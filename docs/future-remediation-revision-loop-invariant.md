# Remediation revision-loop non-execution invariant

This ST5 test/documentation slice proves the revision loop preserves the same
hard authority boundary as the original remediation-text chain.

The covered sequence is:

1. strict live review returns revision_required;
2. a bounded revision request is derived;
3. revised defensive prose is generated;
4. the revised proposal passes its strict persisted handoff;
5. another independent review is requested;
6. the revised prose is independently reviewed;
7. the final review passes its strict persisted handoff.

At every intermediate boundary, code/config generation, tool-call creation,
target interaction, remediation execution, future-state retest, deployment and
attack-path mutation authority remain false. Future semantics remain unresolved
and the security verdict remains not_evaluated.

Even when the final revised prose is approved,
remediation_accepted=true means only that the text passed independent review.
It is explicitly not an execution permit, a future-state result or a security
verdict.

The invariant also proves that authority-flag tampering is rejected and that
live evidence-ledger drift invalidates reuse of the final persisted revised
review.

This slice changes tests and documentation only. It adds no producer, model
gateway, pipeline, scope, activation, execution-policy or target-interaction
behavior.
