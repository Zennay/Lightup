# ST5 classification-review persisted-consumer guard pack

Issue #781 composes the completed, non-overlapping tests/docs-only guard slices
around the final persisted classification-review request consumer from PR #109.

## Pinned production owner

- PR #109 exact head:
  `ad7f54c7a94467eefbc1f9ef9582ac849cb08175`
- Production consumer source remains owned by PR #109.
- This pack changes no `src/lightup/**` path.

## Included contracts

- #332: strict and live rejection preserve caller-owned persisted input,
  recursive container identity, ordering and deterministic failure semantics.
- #334: successful and rejected live validation are observationally read-only
  across typed lineage and StateStore.
- #340: malformed, ambiguous and strict-invalid persisted input fails before
  the live classification-review validator can run.
- #780: the outer persisted boundary accepts only exact built-in JSON text or
  exact built-in object forms; Python `str`/`dict` subclasses are rejected
  before decode/parser dispatch.

The #332/#334/#340 file content is copied unchanged from their exact accepted
heads. #780 is copied unchanged from its exact acceptance head.

## Deliberate exclusion: #336

#336 owns successful-consumer persisted-input atomicity. Its branch is already
claimed by another worker and currently has no child commits beyond the PR #109
parent. This pack therefore does not recreate, replace or pre-empt #336.

When #336 is materially completed, any future successor composition must import
that exact owner output rather than implementing it here.

## Expected proof partition

The already-materialized #332/#334/#340 contracts are intended GREEN and have
independent permanent `vps-bb300bba` exact-head proof receipts.

#780 is intentionally expected RED on the pinned #109 source because
`_persisted_payload()` currently uses broad `isinstance` checks for
`str` and `dict`. The source owner must absorb the narrow exact-type guard
before this pack can become all-green.

No new LightUp canonical run is justified while root evidence-remediation PR
#62 still owns the active queued exact-head proof dependency.

## Semantic stop line

A successful consumer result means only that a persisted classification-review
request survived strict parsing and complete live evidence-remediation lineage
validation. This pack does not perform classification review and cannot select
a classification, create a transition resolution, authorize collection/tool
execution, interact with a target, execute remediation/retest, deploy, create a
security verdict, or mutate attack paths.
