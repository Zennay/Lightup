# ST5 remediation evidence bundle persisted handoff

This boundary sits directly above the remediation-evidence bundle introduced by
PR #60. It protects persisted or transported bundle data without widening any
remediation, retest, target, deployment, or classification authority.

## Persisted integrity

Raw JSON is decoded with duplicate-key rejection at every object level. The
typed parser then requires exact schemas for the bundle, remediation items, and
evidence references. Primitive types are strict, so booleans cannot satisfy
integer fields and truthy non-booleans cannot satisfy authority or readiness
flags.

The parser also verifies:

- canonical lowercase SHA-256 values for report, plan, resolution, evidence,
  evidence-manifest, and bundle digests;
- only INTRODUCED/WORSENED items can appear as remediation authoring inputs;
- remediation and future-state-retest requirements remain exactly true;
- evidence IDs and bundle-item identities remain unique;
- evidence and bundle items preserve producer canonical ordering;
- every per-item evidence-manifest digest is recomputed;
- the complete bundle digest is recomputed;
- authoring readiness is derived only from a non-empty remediation item set
  with zero blocking evidence gaps;
- execution, code-change, target-interaction, deployment, and attack-path
  authority remain false;
- future semantics remain unresolved and the security verdict remains
  not_evaluated.

## Live lineage gate

Successful parsing is not authorization. The composed
`load_and_validate_future_remediation_evidence_bundle` boundary immediately
passes the parsed object to PR #60's
`validate_future_remediation_evidence_bundle`. That rebuilds the bundle from
the current remediation/retest plan, ST4 lineage, RunContexts, and StateStore.
Any ledger or lineage drift therefore fails before persisted data can become an
authoring input.

## Ownership and dependency

This package is stacked on exact PR #60 head
`0f1e3a54ef7bb985e8280f8944223d4a0c9d3d14` and adds new files only. It does
not modify #60's producer/validator implementation, the #190 remediation-plan
handoff, the #62-rooted evidence collection/classification chain, or the
#52-rooted retest/authorization stack.

The PR must remain draft until exact-head hosted Python 3.11/3.14 and canonical
self-hosted `vps-bb300bba` LightUp proofs are green.
