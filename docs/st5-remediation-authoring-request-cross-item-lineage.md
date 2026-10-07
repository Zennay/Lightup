# ST5 remediation authoring-request cross-item lineage acceptance

This tests/docs-only acceptance contract sits directly above exact active #198
remediation authoring-request handoff head
`7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

## Gap

The strict persisted parser currently treats the complete item triple

`(change_node_id, subject_node_id, resolution_id)`

as the only cross-item uniqueness key.

That is weaker than the live producer chain. #196 builds an authoring request
from a live-valid #60 remediation evidence bundle, which in turn derives from
the remediation/retest plan and upstream ST4 transition lineage. That lineage
already prohibits duplicate change identities, duplicate resolution identities,
and one current attack-path identity being claimed by different changes.

A persisted caller can currently append a second otherwise-valid authoring item,
keep the full triple distinct, reuse one independently unique identity, and
recompute the public `request_sha256`. The strict parser can then reconstruct
typed state the canonical producer cannot emit.

## Acceptance

The regression contract requires:

1. an untouched real WORSENED producer request still round-trips;
2. two distinct persisted items cannot reuse one `change_node_id`;
3. two distinct persisted items cannot reuse one `resolution_id`;
4. different changes cannot claim the same `current_attack_path_id`;
5. every forged payload keeps canonical item ordering and recomputes a matching
   `request_sha256`;
6. persisted input is rejected rather than normalized or silently deduplicated.

The cloned second item receives a distinct subject and evidence identity and,
except for the invariant deliberately under test, distinct resolution/path
lineage. This keeps each RED case isolated.

## Non-overlap

Issue #431 adds only this regression module and this contract document. It does
not modify #198/#196 source/tests/docs and does not take source ownership.

It is distinct from:

- #409/#410 capability/path identity shape and ordering;
- #411/#412 canonical evidence kind;
- #413/#414 exact evidence/capability coverage;
- #415/#416 positive twin versions;
- #417/#418 classification/current-path presence semantics;
- #419/#420 canonical resolution/effect lineage;
- #421/#422 item/evidence identity shape;
- #425/#426 top-level lineage identity shape;
- #429/#430, which proves the analogous invariant at the upstream #194 bundle
  persisted boundary.

No model invocation, code/config generation, target interaction, tool execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation is introduced.

## Expected state

Until #198's source owner absorbs this narrow invariant, the canonical producer
control should stay green while the three forged cross-item cases are expected
RED. After absorption, the target is 3 RED -> 0 RED while the parent handoff,
real producer chain and safety canaries remain green.
