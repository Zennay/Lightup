# Future security evidence sufficiency attestation handoff

This ST5 boundary strictly parses persisted
`FutureSecurityEvidenceSufficiencyAttestation` JSON.

The source attestation is an explicit operator review result. It may record
whether evidence is sufficient and whether the evidence's classification claim
is justified, but it still does not select a LightUp classification, create a
transition resolution, or authorize execution.

## Exact disposition semantics

Only three dispositions are valid:

- `insufficient_for_classification`: evidence is not sufficient, more evidence
  is required, classification review is not eligible;
- `sufficient_claim_unjustified`: evidence is sufficient but the evidence's
  classification claim is not justified, so classification review remains
  ineligible;
- `sufficient_claim_justified`: evidence is sufficient and the claim is
  justified, so a later classification-review stage becomes eligible.

The parser recomputes the four derived flags from the disposition and rejects
any persisted mismatch.

## Strict integrity checks

`future_security_evidence_sufficiency_attestation_from_dict(...)` also
requires the exact schema, canonical IDs and lowercase SHA-256 values,
non-empty sorted/unique evidence and capability IDs, an existing transition
classification value retained only as an evidence claim, the three explicit
review-result flags to remain true, every classification/resolution/execution
authority flag to remain false, unresolved future semantics, no security
verdict, and an exactly recomputed `attestation_sha256`.

## Live validation remains mandatory

Parsing proves serialization integrity only. Consumers must still call
`validate_future_security_evidence_sufficiency_attestation(...)` against the
live verifier identity, verifier preflight, sufficiency request, upstream
evidence-remediation lineage and current `StateStore`.

A successful round trip therefore cannot turn an operator attestation into a
selected security classification or any target/tool/remediation/retest/deploy
authority.

## Safety boundary

This package performs no evidence collection, target interaction, tool
invocation, remediation authoring, retest execution, deployment or attack-path
mutation.
