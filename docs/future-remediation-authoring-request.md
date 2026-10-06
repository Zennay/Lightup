# ST5 bounded remediation authoring request

This package is the next planning-only step after the remediation evidence
bundle. It converts a live-valid, authoring-ready bundle into immutable metadata
for a later remediation-advisor stage.

It deliberately does **not** call the Model Gateway or current
`AssessmentReviewPipeline`. It also does not generate code/config, invoke a
tool, interact with a target, execute remediation or a retest, merge, or deploy.

## Input gate

`build_future_remediation_authoring_request` first calls PR #60's
`require_future_remediation_evidence_bundle_for_authoring`. The source bundle
must therefore still rebuild exactly from the current remediation/retest plan,
ST4 lineage, RunContexts, and StateStore, and it must have no blocking evidence
gap.

Improved, removed, or insufficient-evidence outcomes cannot produce an
authoring request. Only evidence-ready introduced/worsened items are eligible.

## Bounded authoring metadata

Each request item preserves only:

- change, subject, and transition-resolution identity;
- classification;
- current attack-path and effect IDs;
- capability IDs;
- bounded evidence references: evidence ID, run ID, capability ID, kind, and
  SHA-256;
- the evidence-manifest SHA-256;
- the fixed requested output `remediation_text_proposal`.

No raw evidence payload, source/config content, credentials, target arguments,
or patches are exported by this request.

## Authority boundary

The request says only that remediation **text authoring is requested**:

- `authoring_requested=true`
- `remediation_proposal_created=false`
- `code_change_authorized=false`
- `tool_call_created=false`
- `execution_allowed=false`
- `target_interaction_allowed=false`
- `future_state_retest_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

A later model-generated proposal would still require a separate validation and
approval boundary before any code/config or active action.

## Determinism and live validation

Items are canonically ordered by change/subject/resolution identity. The request
has a deterministic SHA-256 bound to the exact evidence bundle and all bounded
item metadata.

`validate_future_remediation_authoring_request` rebuilds the request through
the full live evidence-bundle readiness gate and requires exact dataclass
equality, so later evidence/ledger/lineage drift invalidates an existing
request.

## Dependency / ownership

This slice is stacked on exact PR #194 head
`ec4b09f539289fbf3b497a534980323bd3c11bef`, which is stacked on #60.
It adds new files only and does not modify the current AI pipeline, #60/#194,
the #62-rooted evidence-collection/classification stack, or the #52-rooted
retest/authorization stack.

Refs #195.
