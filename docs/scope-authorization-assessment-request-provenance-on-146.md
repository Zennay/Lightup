# Scope authorization — assessment-request provenance on active domain head

This composition restacks the assessment-request provenance acceptance pack
above exact active risk/decision source owner #146.

## Exact parent

`33c67f8e8b17bd9214c29d02fc52954cc42655da`

## Regression status on #146

Already source-green on this parent:

- #875: assessment-request `requested_risk` is validated as a real
  `RiskLevel` before persistence;
- #876: assessment-request `requested_mode` is validated as a real
  `AssessmentMode` before persistence.

Their tests stay in the pack as regression locks, not as open expected-RED gaps.

Still expected RED on this parent:

- #877: persisted `requested_assets_json` can still be reinterpreted through
  generic iteration instead of failing closed on corrupt durable shape;
- #880: persisted request `status`, `decided_by` and `decided_at` are still
  reconstructed independently without lifecycle/provenance coherence checks.

## Ownership

The composition is tests/docs only. It does not modify `src/lightup/domain.py`.
#146 retains risk/decision source ownership, #177 retains request-to-grant
issuance semantics, and #877/#880 remain the unresolved read-side contracts.

## Safety

Temporary-SQLite authorization-provenance acceptance only. No DNS/network I/O,
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
