# ST5 fresh-evidence coverage

This package aggregates **freshness only** across unresolved evidence gaps.

It answers one narrow question:

> Does every unresolved gap currently have a live-valid admission containing
> candidate evidence that is fresh relative to the prior insufficient evidence?

It does not answer whether that candidate evidence is relevant, sufficient or
supports any security classification.

## Inputs

`build_future_security_evidence_freshness_coverage` consumes:

- the live freshness constraints;
- zero or more typed freshness admissions;
- the exact candidate `RunContext` for every supplied admission;
- the full request/ST4/ST5 lineage and live StateStore needed to revalidate all
  inputs.

Every supplied admission is revalidated through
`validate_future_security_evidence_freshness_admission` before it can affect
coverage.

Foreign or duplicate source-resolution admissions fail closed. Candidate
RunContexts must bind one-to-one to supplied admissions; missing or unreferenced
contexts are rejected.

## Coverage semantics

The report always emits one canonical item for every freshness-constraint gap.

An item is either:

- `fresh_candidate_present=true`, bound only to the admission digest,
  candidate run ID and candidate evidence IDs; or
- `fresh_candidate_present=false`, with no admission/run/evidence identity.

Aggregate fields are:

- `total_gap_count`;
- `covered_gap_count`;
- `missing_gap_count`;
- `all_gaps_have_fresh_candidates`.

Even when all gaps have fresh candidates, the report explicitly retains:

- `evidence_sufficiency_evaluated=false`;
- `gap_closed=false`;
- `classification_selected=false`;
- `transition_resolution_created=false`;
- `security_verdict=not_evaluated`.

Therefore freshness coverage can never become a PASS/clean/fixed claim.

## Determinism and persistence

Items are canonically ordered by change, subject and source resolution. The
`coverage_sha256` binds the exact freshness constraints, coverage identities,
counts and safety semantics.

Persisted reports must be passed through
`validate_future_security_evidence_freshness_coverage`, which rebuilds every
admission against live evidence and requires exact report equality.

The export contains IDs and digests only; it does not copy evidence payloads,
metadata, source locations, targets, arguments or credentials.

## Safety boundary

- `evidence_sufficiency_evaluated=false`
- `gap_closed=false`
- `classification_selected=false`
- `transition_resolution_created=false`
- `collection_authorized=false`
- `tool_call_created=false`
- `execution_allowed=false`
- `target_interaction_allowed=false`
- `remediation_authoring_allowed=false`
- `future_state_retest_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

Refs #73.


## Strict serialized handoff

Persisted coverage JSON must be parsed with
`future_security_evidence_freshness_coverage_from_dict`.

The parser derives coverage semantics from item content rather than trusting
stored counters:

- covered items must carry a canonical admission SHA-256, candidate run ID and
  non-empty sorted/unique candidate evidence IDs;
- uncovered items must carry no admission digest, no candidate run and no
  candidate evidence IDs;
- item identities must be canonical and unique;
- total, covered and missing counts are recomputed from the items;
- `all_gaps_have_fresh_candidates` is recomputed rather than trusted;
- every sufficiency, closure, classification and execution flag remains
  fail-closed.

The parser also recomputes `coverage_sha256`. Parsing proves serialization
integrity only. Before use, consumers must still run
`validate_future_security_evidence_freshness_coverage`, which revalidates the
underlying admissions against live evidence.
