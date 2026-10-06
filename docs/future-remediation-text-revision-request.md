# Future remediation text revision request

This ST5 boundary turns one strict, still-live remediation-text review with the
decision revision_required into a bounded request to revise the prose.

It is deliberately separate from remediation execution and from evidence
collection.

## Decision routing

The request builder accepts only revision_required.

- approved is rejected because accepted prose must not silently re-enter a
  rewrite loop.
- insufficient_evidence is rejected because an evidence gap must return to
  evidence collection instead of being disguised as a wording problem.
- revision_required records the review checks whose result is not pass,
  preserving the canonical review-rubric order.

## Live lineage

Before a revision request can exist, the persisted review must pass the strict
review handoff, which in turn revalidates the review request, proposal and live
evidence lineage. The revision request binds the exact review, review-request,
proposal and content SHA-256 values and emits its own deterministic digest.

## Authority stop line

The artifact means only "revision of remediation text was requested".

It does not authorize code/config generation, tool calls, target interaction,
remediation execution, future-state retesting, deployment, attack-path
mutation, future-state resolution or a security verdict. All of those authority
flags remain false and future semantics remain unresolved.
