# ST4 transition-verification evidence input integrity

Issue: #866

The ST4 transition-verification boundary treats fresh evidence identifiers as typed security lineage, not as a normalization input.

## Invariant

For `verify_future_attack_path_transition(..., evidence_ids=...)` and live/direct resolution revalidation:

- the evidence container is an exact built-in `tuple`;
- every member is an exact built-in `str`;
- existing non-empty, canonical sorting, uniqueness, identifier bounds, freshness, metadata, run and StateStore checks remain unchanged;
- caller lists, tuple subclasses and string subclasses fail closed before sorting, digest comparison or evidence lookup can repair/coerce them;
- canonical tuple input may still be sorted by the builder as before.

## Deliberate boundary

This change applies only to transition-verification `evidence_ids`. It does not alter `capability_ids`, `effect_ids`, `current_attack_path_ids`, classification semantics, evidence collection, target interaction, remediation/retest execution, deployment, security verdicts or attack-path mutation.

## Safety

This is an input-integrity narrowing. It grants no new authority and performs no network or target interaction.
