# Evidence → remediation → retest temporal lineage (offline reference)

Status: **proposed reference, not a production enforcement claim**. M7/ST5 remains fail-closed; no active target authorization is introduced.

## Motivation
A finding can carry apparently valid evidence references while its remediation or retest evidence predates the observation or fix, or belongs to another finding. Before describing an outcome as *retested*, ingestion should require a verifiable sequence of distinct evidence records.

## Proposed contract
- Three separate immutable evidence references: original observation, remediation action, subsequent retest.
- Each record uses exact built-in dictionary keys `evidence_id`, `finding_id`, `at`; identities are exact nonblank built-in strings and no more than 128 characters.
- All records refer to the same exact finding ID, with three distinct evidence IDs.
- Timestamps in this illustrative reference must be bounded ISO-8601 strings with an explicit UTC offset of zero; strictly `observation < remediation < retest`.
- Invalid, noncanonical, cross-finding, duplicated or nonmonotonic records fail closed with stable `ValueError` and without modifying caller data.
- Passing the reference means only that this toy lineage is internally consistent. It does **not** prove issuer provenance, signature integrity, original collection time, permissions, a real fix, a successful retest, or any security verdict.

## Ownership and promotion
This addition intentionally contains only `tests/test_evidence_temporal_lineage_reference.py` and this document. It does not edit existing evidence / finding / reporting / remediation / retest implementations or overlap source-owning PRs. Runtime production owners must decide trusted timestamp origin, persistence transaction guarantees, delayed/out-of-order ingestion semantics and whether a remediation event is applicable. A source-owner integration, exact-head hosted CI and canonical permanent VPS CI plus review are required before claiming production coverage.

## Offline regression coverage
The reference suite contains 20 tests covering strict event ordering, equal-time rejection, input and identity type confusion, cross-finding references, duplicate evidence, timestamp bounds, caller immutability, and unknown authority-bearing fields. These checks are pure stdlib unit tests; they do not exercise production persistence or retest dispatch.

Offline invocation: `python -m unittest discover -s tests -p 'test_evidence_temporal_lineage_reference.py' -v`.

No DNS, sockets, scanning, assessment execution, target contact, grant activation, active remediation, deployment or verdict mutation.
