# Future attack-path transition proposals

This ST3 slice sits between verified future impact analysis and any later
attack-path mutation stage.

It is intentionally **proposal-only**.

## Input boundary

`propose_future_attack_path_transitions` accepts only a
`FutureAttackPathImpactReport`.

Before deriving a proposal it reruns
`validate_future_attack_path_impact_report`, so the exact analysis digest,
Current/Future Twin lineage, ChangeSet identity, impact items and fixed
`future_semantics=unresolved` / `security_verdict=not_evaluated` boundary
must still match.

A report that was edited after analysis is rejected before proposal generation.

## Conservative proposal actions

| Impact | Existing attack path | Proposal action |
| --- | --- | --- |
| `potential_regression` | yes | `review_existing_paths_for_regression` |
| `potential_regression` | no | `review_new_path_hypothesis` |
| `potential_improvement` | yes | `review_existing_paths_for_improvement` |
| `potential_improvement` | no | `review_improvement_without_path_claim` |
| `mixed` | either | `manual_transition_review` |
| `unchanged` | either | `no_transition_claim` |

A new-path hypothesis is only a review request. It is not an AttackPath,
AttackStep, exploitability finding or proof that a new route exists.

## Output contract

Every proposal item preserves only identifiers and evidence lineage already
present in the verified impact report:

- change node ID;
- verified subject ID;
- graph resolution ID;
- subject decision ID;
- materialization resolution ID;
- verified effect IDs;
- current attack-path IDs as read-only references;
- impact label;
- conservative review action;
- evidence references.

The proposal additionally carries:

- the exact source `impact_analysis_sha256`;
- a canonical `proposal_sha256`;
- `proposal_complete=true`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

The proposal digest binds the complete proposal payload and the source analysis
digest. Replaying the same verified input therefore produces the same proposal.

## Fail-closed validation

`validate_future_attack_path_transition_proposal` rejects:

- incomplete proposals;
- mutation-enabled proposals;
- security verdicts;
- resolved future semantics;
- duplicate change identities;
- unsupported impact labels;
- non-canonical review actions;
- missing effect lineage;
- duplicate, malformed or non-canonically ordered identifiers;
- proposal digest mismatches.

## Safety boundary

This module never accepts or returns a mutable Security Twin. It does not add,
remove, reorder or rewrite `AttackPath` or `AttackStep` objects.

The canonical VPS proof for the merged impact-analysis stage remains required
evidence before a later independently verified mutation stage may be considered.

No target interaction, network execution, authorization widening, credential
use, exploit generation or deploy approval is introduced here.
