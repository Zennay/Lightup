# ST4 attack-path transition verification

This stage is the first independently verified step after the read-only ST3
transition proposal. It can classify one proposed transition, but it still does
not mutate a Security Twin or an AttackPath and it does not issue a deployment
verdict.

## Input boundary

`verify_future_attack_path_transition` accepts only a validated
`FutureAttackPathTransitionProposal`. The selected item remains bound to:

- the exact proposal SHA-256;
- the exact source impact-analysis SHA-256;
- client, change-node and verified subject identity;
- exact effect IDs;
- exact referenced current attack-path IDs;
- the proposal's canonical review action.

The review action limits which classifications are even eligible for
verification. A new-path hypothesis, for example, can become `introduced`
only after fresh evidence; it cannot become `worsened` because there is no
referenced current path to worsen.

## Fresh evidence contract

Before evidence is stored,
`future_attack_path_transition_evidence_contract` returns the exact metadata
that a new isolated-lab evidence record must carry. The contract includes the
deterministic resolution ID and binds the evidence to:

- purpose `future_attack_path_transition_verification`;
- proposal and impact-analysis digests;
- immutable lab RunContext: client, engagement, mode and `is_lab=true`;
- change and subject IDs;
- proposed classification;
- canonical SHA-256 digests of effect IDs and referenced current path IDs.

Resolution evidence must be fresh: evidence already referenced by the ST3
proposal item cannot be reused as ST4 proof.

Every evidence record is re-read from the live evidence ledger during
validation. Its run, kind, metadata and capability are checked again. Deleted,
cross-run, cross-client or metadata-mismatched evidence therefore fails closed.

## Classifications

The verified classification vocabulary is intentionally small:

- `introduced`
- `removed`
- `worsened`
- `improved`
- `insufficient_evidence`

Compatibility is constrained by the proposal action:

| Proposal action | Allowed verified classifications |
| --- | --- |
| `review_new_path_hypothesis` | `introduced`, `insufficient_evidence` |
| `review_existing_paths_for_regression` | `worsened`, `insufficient_evidence` |
| `review_existing_paths_for_improvement` | `improved`, `removed`, `insufficient_evidence` |
| `review_improvement_without_path_claim` | `insufficient_evidence` |
| `manual_transition_review` | any classification above |
| `no_transition_claim` | `insufficient_evidence` |

`removed`, `worsened` and `improved` additionally require at least one
referenced current attack path. Conversely, `introduced` is only valid when no
current attack path is referenced; even manual review cannot label an existing
path as newly introduced.

## Resolution identity

A resolution has a deterministic stable ID over the exact proposal/analysis
lineage, change, subject, classification, run, effect IDs and current path IDs.
Its `resolution_sha256` additionally binds the fresh evidence IDs and
capability IDs.

Exact replay of the same evidence is deterministic. A changed evidence set or
capability set changes the resolution digest and cannot silently pass as the
same validated handoff.

## Safety boundary

This module exposes no API that adds, removes or edits attack paths. It performs
no target interaction itself, cannot widen authorization, and keeps
`security_verdict=not_evaluated`.

A later ST4 graph-diff stage may consume independently verified transition
resolutions. That later stage must preserve evidence lineage and remain
separate from the eventual ST5 CI verdict policy.
