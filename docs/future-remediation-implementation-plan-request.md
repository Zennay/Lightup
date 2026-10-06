# Future remediation implementation-planning request

This ST5 contract is the first boundary after an independent verifier has
accepted remediation prose. It requests a later **implementation plan**, but it
does not contain or generate implementation material itself.

Construction requires the strict persisted remediation review handoff to remain
live-valid and requires all three conditions:

- the review is completed;
- the review decision is `approved`;
- `remediation_accepted=true`.

The request binds the exact review, review-request, proposal and remediation
content SHA-256 values plus reviewer provenance and remediation item count.

## No implementation authority

The request intentionally contains no remediation body, patch, code/config,
command, tool arguments, target arguments, credentials, evidence source or
arbitrary evidence metadata.

Only `implementation_planning_requested=true` advances. The request keeps
`implementation_plan_created=false`, and code-change, tool-call, execution,
target-interaction, future-state-retest, deployment and attack-path-mutation
authority all remain false. Future semantics stay unresolved and the security
verdict remains `not_evaluated`.

A later contract may produce a reviewable implementation **plan**, but code
application and execution authorization must remain separate boundaries.
