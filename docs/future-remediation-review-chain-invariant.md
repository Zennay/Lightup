# Future remediation review chain invariant

This test-only slice proves the complete ST5 remediation-text path remains a
planning and review chain rather than an execution path.

The exercised route is:

1. live-valid remediation authoring request;
2. remediation-advisor text proposal;
3. strict persisted proposal handoff;
4. independent review request;
5. structured verifier review;
6. strict persisted review handoff.

An approved verifier result may set `remediation_accepted=true` for the
**prose**. It still leaves code/config changes, tool calls, target interaction,
remediation execution, future-state retest, deployment and attack-path mutation
unauthorized. Future semantics remain unresolved and no security verdict is
produced.

Revision-required and insufficient-evidence decisions remain unaccepted. The
chain also revalidates live evidence lineage before persisted review reuse, so
later evidence drift invalidates a previously accepted text review.
