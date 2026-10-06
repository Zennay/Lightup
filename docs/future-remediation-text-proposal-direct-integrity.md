# Remediation text-proposal direct-construction integrity

`FutureRemediationTextProposal` remains planning prose only. Its constructor
now enforces the same metadata and digest invariants as the strict persisted
handoff, so an in-memory caller cannot manufacture a proposal that only becomes
invalid after serialization.

Direct construction requires:

- the exact proposal schema version;
- canonical lowercase SHA-256 request, bundle, content and proposal digests;
- a positive integer item count, with bool/int confusion rejected;
- non-empty provider and model provenance;
- bounded non-empty proposal content with NUL rejected;
- a content digest that matches the exact proposal text;
- the existing plan-only lifecycle and action-authority stop line;
- a full proposal SHA-256 that recomputes from lineage, provenance, content and
  canonical safety state.

Changing request/bundle lineage or proposal content while retaining a stale
proposal digest therefore fails immediately at construction.

This is integrity narrowing only. It adds no model invocation, target
interaction, tool execution, remediation execution, retest, deployment,
future-state resolution, security verdict, or attack-path mutation.
