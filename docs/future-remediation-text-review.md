# Future remediation text review

This ST5 slice performs the independent review requested by the preceding
review-request contract. It uses the existing provider-neutral `verifier`
model role after the review request and proposal have both passed their strict
live-lineage handoffs.

The verifier receives the exact proposal text plus the four fixed checks:
evidence alignment, unsupported claims, least privilege, and future-retest
separation. All input is treated as untrusted data.

The verifier must return strict JSON with:

- `decision`: `approved`, `revision_required`, or
  `insufficient_evidence`;
- one `pass`, `fail`, or `unclear` result for every required check;
- a bounded non-empty summary.

An `approved` decision is accepted only when every check passes.
`revision_required` requires at least one non-pass result, and
`insufficient_evidence` requires at least one unclear result.

## Acceptance is not execution authority

When every review check passes, `remediation_accepted=true` means only that
the **text proposal** passed this review contract. It does not authorize code or
configuration changes, tool calls, target interaction, remediation execution,
future-state retest, deployment, or attack-path mutation.

Future semantics remain `unresolved` and the security verdict remains
`not_evaluated`. A later contract must explicitly govern any transition from
accepted text into a proposed implementation, and that contract must remain
separate from execution authorization.
