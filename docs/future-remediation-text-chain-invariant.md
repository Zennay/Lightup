# Future remediation text chain invariant

This test-only slice proves the current evidence-remediation authoring stack
remains a planning chain, not an execution path.

The exercised route is:

1. persisted remediation authoring request;
2. strict request parsing and live-lineage revalidation;
3. `remediation_advisor` text generation;
4. persisted remediation text proposal;
5. strict proposal parsing, digest verification and live-lineage revalidation.

The invariant intentionally distinguishes **text exists** from **action is
authorized**. After successful model authoring, only
`remediation_proposal_created` advances to true. Code changes, tool calls,
target interaction, remediation execution, future-state retest, deployment and
attack-path mutation remain false. Future semantics remain unresolved and the
security verdict remains `not_evaluated`.

The regression also mutates the live evidence ledger after generation and
proves that both request reuse and proposal reuse fail. Persisted model prose
therefore cannot bypass later lineage drift merely because its own digest is
internally consistent.
