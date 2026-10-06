# ST5 remediation authoring request persisted handoff

This boundary protects persisted or transported
`FutureRemediationAuthoringRequest` data before any later remediation-advisor
stage can consume it.

## Strict parsing

Raw JSON is decoded with duplicate-key rejection at every object level. The
typed parser then requires exact request/item/evidence schemas and strict
primitive types.

The boundary verifies:

- canonical lowercase SHA-256 values for report, plan, bundle, resolution,
  evidence, evidence-manifest, and request digests;
- only introduced/worsened classifications;
- the fixed requested output `remediation_text_proposal`;
- `authoring_requested=true`;
- remediation and future-state-retest requirements stay true on each item;
- evidence capability IDs remain inside the item capability lineage;
- unique, canonical evidence and request-item ordering;
- per-item evidence-manifest digest recomputation;
- full request digest recomputation;
- proposal/code/tool/target/execution/retest/deploy/attack-path authority stays
  false;
- future semantics stay unresolved and the security verdict stays
  not_evaluated.

## Live composition

Parsing is not authorization.
`load_and_validate_future_remediation_authoring_request` immediately passes
the parsed request to #196's live validator. That rebuilds the authoring request
through #60's live remediation evidence-bundle readiness gate and the current
ST4/ST5 lineage plus StateStore.

A syntactically canonical persisted request therefore still fails closed when
its source evidence, bundle, plan, report, run context, or transition lineage
has drifted.

## Safety stop line

This package does not invoke the Model Gateway, generate remediation text,
create code/config, construct a tool call, interact with a target, execute a
retest, merge, or deploy.

## Dependency / ownership

This slice is stacked on exact PR #196 head
`f559e28e4ce213daa831effed95e671154ba5d8e`. It adds new files only and does
not modify #196/#194/#60, the current AI pipeline, the #62 evidence-collection
and classification chain, or the #52 retest/authorization chain.

Refs #197.
