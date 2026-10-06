# Remediation authoring-item direct-construction integrity

`FutureRemediationAuthoringRequestItem` is planning metadata inside an ST5
remediation authoring request. Its direct in-memory constructor now enforces the
same fail-closed contract as the strict persisted handoff.

The constructor requires:

- non-empty change, subject and resolution identifiers;
- canonical lowercase SHA-256 values for the resolution and evidence manifest;
- an actual authoring-eligible `AttackPathTransitionClassification`
  (`introduced` or `worsened`);
- tuple-typed lineage collections with non-empty strings and no duplicates,
  with at least one capability;
- a non-empty tuple of exact `RemediationAuthoringEvidenceRef` records;
- non-empty evidence identifiers/provenance fields and canonical evidence
  SHA-256 values;
- every evidence capability to be present in the item capability lineage;
- unique, canonically ordered evidence IDs;
- an evidence-manifest digest that exactly matches the evidence records;
- `requested_output == "remediation_text_proposal"`;
- exact boolean `True` for `remediation_required` and
  `future_state_retest_required`.

This closes the gap where a caller could construct a nested item in memory that
would be rejected only later by the persisted parser. Boolean/int confusion,
raw-string enum lookalikes, malformed evidence containers and stale/forged
manifest values now fail at construction.

This change is integrity-only. It adds no tool call, target interaction,
remediation execution, retest execution, deployment authority, future-state
resolution, security verdict, or attack-path mutation.
