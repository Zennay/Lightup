# ST5 remediation/retest required-lineage acceptance

Issue: #383

This acceptance contract is a tests/docs-only child of the exact draft PR #190 head
`c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`.

## Boundary

The persisted remediation/retest-plan handoff must preserve the required lineage
collections already enforced by the upstream ST4 transition-resolution validator.

For every persisted plan item:

- `effect_ids` must remain non-empty;
- `evidence_ids` must remain non-empty;
- `capability_ids` must remain non-empty.

`current_attack_path_ids` is intentionally excluded from this universal
non-empty rule because its valid shape depends on the transition classification.

The acceptance re-signs every tampered payload with a matching `plan_sha256`.
Passing the contract therefore requires explicit lineage validation rather than
incidental stale-digest rejection.

## Expected RED on #190

At exact #190, `_string_tuple` validates list shape, non-empty string entries
and duplicate membership, but it accepts an empty list. Consequently an attacker
or corrupted persisted record can erase one of the upstream-required lineage
collections, recompute the public plan digest, and reconstruct a typed plan.

The dedicated regression therefore intentionally expects three rejection cases
that are RED until the #190 source owner absorbs the invariant.

## Collision boundary

This branch adds only this document and
`tests/test_future_security_remediation_retest_required_lineage_acceptance.py`.

It does not modify #190 source/tests/docs and does not touch the files owned by
#377, #378, or #381.

## Safety

Persistence-integrity only. No evidence collection, model invocation, target
interaction, tool execution, remediation/retest execution, deployment, security
verdict creation, or attack-path mutation is introduced.
