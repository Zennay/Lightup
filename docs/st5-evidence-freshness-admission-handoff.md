# ST5 evidence freshness admission handoff

This slice is a serialization-integrity boundary for
`FutureSecurityEvidenceFreshnessAdmission`.

It accepts only the exact persisted schema emitted by the read-only freshness
admission stage. Candidate evidence fingerprints are bounded to evidence ID,
run ID, capability ID, kind, and canonical SHA-256. Candidate evidence must be
canonically ordered, unique, bound to exactly one candidate run, and its
serialized evidence/capability lists must exactly match the fingerprints.

The parser also preserves the fail-closed safety boundary:

- `freshness_check_passed=true`;
- evidence suitability is not evaluated;
- no security classification or transition resolution is selected;
- evidence collection is not authorized;
- no tool call or target interaction is created;
- remediation authoring, future-state retest, deployment, and attack-path
  mutation remain unauthorized;
- future semantics remain `unresolved`;
- security verdict remains `not_evaluated`.

The parser recomputes `admission_sha256` over the canonical typed admission and
rejects mismatches.

Serialization integrity is not live trust. Before downstream use, consumers
must still call
`validate_future_security_evidence_freshness_admission(...)` against the live
freshness constraints, request, upstream ST4/ST5 lineage, candidate
`RunContext`, and current `StateStore`.

Dependency order for this stacked slice is:

`#62 -> #64 -> #66 -> #68 -> #69 -> #70`.

No merge or promotion is valid until every dependency has landed and this exact
head has fresh hosted Python 3.11/3.14 plus canonical
`vps-bb300bba` proof.
