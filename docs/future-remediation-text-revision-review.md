# Independent review of revised remediation text

This ST5 slice performs the independent verifier decision requested by the
strict revised-remediation review-request handoff.

Before any verifier invocation, both the persisted review request and the exact
revised proposal must pass their strict live-lineage validators. That
transitively revalidates the revision request, prior review, original proposal
and current evidence ledger.

The existing provider-neutral verifier role receives only the revised proposal
text, required check names and lineage identifiers. All proposal text and
identifiers are treated as untrusted data.

The verifier returns strict JSON containing a decision, one result for each
fixed review check, and a bounded summary. Duplicate JSON keys, unknown fields,
invalid check results and incoherent decisions fail closed.

An approved decision sets remediation_accepted=true for the **revised prose
only**. Code/config generation, tool calls, target interaction, remediation
execution, future-state retesting, deployment, future-state resolution,
attack-path mutation and security-verdict authority all remain false or
unresolved.
