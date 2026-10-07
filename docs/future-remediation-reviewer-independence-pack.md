# Remediation reviewer-independence acceptance pack

Issue: #812

## Composition

This branch composes two tests/docs-only acceptance contracts on top of the
current revised-remediation review producer:

- #810 — first-pass remediation proposal author cannot be the exact reviewer
  provider/model pair;
- #811 — revised-remediation proposal author cannot be the exact reviewer
  provider/model pair.

The current downstream source parent is PR #246 exact head
`d995cf57e20f99956fe20b9b8b05d41b64e02765`. That head is 24 commits ahead
and 0 behind PR #217 exact source head, so both producer modules are present in
one lineage.

## Acceptance posture

The existing distinct reviewer fixtures are green controls.

Both exact self-review cases are intentionally expected RED until their
respective source owners add a pre-invocation identity-separation check.

No source repair is owned by this composition branch.

## Ownership

- PR #217 owns `review_future_remediation_text()`;
- PR #246 owns `review_future_remediation_text_revision()`;
- #810 and #811 own their individual acceptance proofs;
- #812 owns composition only.

## Safety

Tests/docs-only provenance hardening. No external model/network call, target
interaction, scanning, code/config application, remediation/retest execution,
deployment, security verdict or attack-path mutation.
