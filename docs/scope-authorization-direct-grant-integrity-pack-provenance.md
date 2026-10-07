# Direct grant policy integrity pack — approval provenance successor

Issue: #778

This branch extends the existing #744 direct-grant policy integrity acceptance head with the independent #777 approval-provenance boundary.

## Included acceptance families

The inherited #744 pack keeps its existing durable direct-grant contracts, including time integrity, revocation coherence, exact outer grant/scope identity, and exact client/engagement lineage identity.

This successor adds only:

- #777 exact/canonical direct `approved_by` provenance;
- #777 exact/canonical direct `reference` provenance;
- canonical direct TARGET_ACTIVE grant as a green control;
- blank, whitespace-only, padded, and polymorphic provenance as expected-RED controls on the pinned PR #100 source.

## Source ownership

No production source is changed here. PR #100 remains the production owner.

This composition does not absorb:
- #649 issuance provenance input typing;
- #475/#554 persisted provenance resolution;
- #737 revocation provenance;
- #773/#775/#776 direct ScopeDefinition risk/collection integrity;
- any orchestration, activation, target-capable, evidence-remediation, remediation/retest, deployment, verdict, or attack-path source.

## Validation and runner stop line

The branch is intended as a future exact-head acceptance proof after the active source owner absorbs the relevant narrowing guards. Do not create or retrigger a self-hosted workflow while the permanent LightUp queue is saturated.

## Safety

Tests/docs-only authorization narrowing. No network or target activity and no execution authority is added.
