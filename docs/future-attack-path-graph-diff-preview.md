# ST4 attack-path graph diff preview

This stage consumes independently verified
`FutureAttackPathTransitionResolution` records and produces a deterministic,
read-only preview of how the attack-path graph would need to change.

It does **not** mutate `SecurityTwin.attack_paths`, does not authorize
deployment, and keeps `future_semantics=unresolved` and
`security_verdict=not_evaluated`.

## Input boundary

`build_future_attack_path_graph_diff_preview` requires:

- one validated `FutureAttackPathTransitionProposal`;
- exactly one verified transition resolution for every proposal item;
- the exact immutable `RunContext` for every resolution run;
- live access to the evidence ledger so every resolution is revalidated.

Resolution and context sets must match the proposal exactly. Duplicate
resolution identities, duplicate change resolutions, missing runs, extra runs,
cross-tenant evidence, deleted evidence, stale metadata, or other resolution
validation failures abort the preview.

## Preview actions

The preview maps verified classifications to descriptive actions only:

| Verified classification | Preview action |
| --- | --- |
| `introduced` | `add_path_hypothesis` |
| `removed` | `remove_existing_path_candidate` |
| `worsened` | `modify_existing_path_risk_up` |
| `improved` | `modify_existing_path_risk_down` |
| `insufficient_evidence` | `no_graph_change_claim` |

These are review semantics, not executable mutations. In particular,
`add_path_hypothesis` does not synthesize or persist an `AttackPath`.

## Collision handling

A current attack path may not be claimed by multiple different change
resolutions in the same preview. Such a collision requires a later explicit
aggregation/conflict-resolution stage and therefore fails closed here.

## Deterministic handoff

The preview SHA-256 binds:

- current and future twin identity/version;
- changeset, proposal and impact-analysis digests;
- every transition resolution identity/digest;
- classification and preview action;
- effect, evidence, capability and current-path lineage;
- the explicit insufficient-evidence flag;
- the non-mutation and non-verdict boundary.

Exact replay is deterministic. Changing any verified input changes the preview
digest.

## Remaining ST4 work

This first slice proves introduced and insufficient-evidence paths and the
coverage/context boundaries. The next increment should add full valid fixtures
for `removed`, `worsened` and `improved`, plus collision regressions over
real existing-path proposals, before this preview can become the handoff to a
separate apply-policy stage.

No real-target interaction, exploit execution, credential use, authorization
widening or deployment approval belongs in this stage.
