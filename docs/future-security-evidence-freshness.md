# ST5 evidence freshness constraints

This package is a planning-only evidence-remediation layer above the unresolved
evidence collection request. It makes freshness explicit by recording exactly
which prior evidence IDs and run IDs **cannot** satisfy the next collection
attempt.

It does not choose or authorize a capability, tool, target, argument,
credential, payload, or transition outcome.

## Source validation

`build_future_security_evidence_freshness_constraints` first runs the complete
live validator for `FutureSecurityEvidenceCollectionRequest`. That rebuilds
the ST5 remediation/retest plan from the live ST4 lineage before the freshness
contract trusts any serialized or persisted request.

For every unresolved item, the builder then resolves the exact source
transition resolution and re-reads every prior evidence record from
`StateStore`.

The live evidence must still match:

- the request's exact prior evidence IDs;
- the source resolution's run ID;
- the request's prior capability lineage;
- a canonical lowercase SHA-256 digest.

Any deletion or drift fails closed.

## Explicit non-reuse constraints

Each gap item exposes:

- `forbidden_evidence_ids`: every evidence ID already used by the
  insufficient-evidence resolution;
- `forbidden_run_ids`: every run that produced that prior evidence;
- bounded prior-evidence fingerprints containing only evidence ID, run ID,
  capability ID, kind and SHA-256;
- `fresh_evidence_required=true`;
- `fresh_run_required=true`.

These fields do not imply which capability should run next. Prior capability
IDs are provenance, not a future capability selection.

## Determinism and live revalidation

Items and evidence fingerprints are canonically ordered. The
`constraints_sha256` binds the exact request identity, lineage, forbidden IDs
and all safety flags.

Persisted constraints must be passed through
`validate_future_security_evidence_freshness_constraints` before use. The
validator rebuilds the constraints against the current evidence ledger and
requires exact equality.

## Safety boundary

This contract cannot authorize collection or remediation:

- `collection_authorized=false`
- `capability_selected=false`
- `tool_call_created=false`
- `execution_allowed=false`
- `target_interaction_allowed=false`
- `remediation_authoring_allowed=false`
- `future_state_retest_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

A later explicitly gated LAB-only package may determine how to obtain new
evidence. It must reject the forbidden evidence/run identities and independently
pass the existing authorization/tool-policy boundaries.

Refs #65.


## Strict serialized handoff

Persisted or cross-stage freshness JSON must be parsed with
`future_security_evidence_freshness_constraints_from_dict`.

The parser rejects missing or extra fields, malformed primitive types,
non-canonical SHA-256 values, non-list lineage, duplicate/non-canonical arrays,
duplicate item identities and any safety flag that attempts to enable
collection or execution.

It also enforces semantic equivalence between the embedded prior-evidence
fingerprints and the explicit non-reuse sets:

- `forbidden_evidence_ids` must exactly equal the prior evidence IDs;
- `forbidden_run_ids` must exactly equal the unique prior run IDs;
- `prior_capability_ids` must exactly equal the capabilities represented by
  prior evidence.

The parser recomputes `constraints_sha256` before returning a typed object.
This is only a serialization-integrity boundary. Consumers must still run
`validate_future_security_evidence_freshness_constraints` against the live
request, source lineage and StateStore before use.
