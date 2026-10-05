# Future attack-path impact analysis

This ST3 slice is a read-only consumer of verified Future Security graph state.

## Preconditions

`analyze_future_attack_path_impact` accepts a future twin only after:

- tenant access has been resolved through `AccessContext`;
- subject decisions are canonical and still backed by live ledger evidence;
- every represented change has a verified graph resolution;
- graph facts, graph relationships, effect semantics and evidence lineage pass the existing ST3 validators;
- future semantics remain explicitly `unresolved`;
- an explicit current Security Twin baseline is supplied;
- current and future belong to the same client;
- the future twin's persisted `future_base_twin_id` and `future_base_twin_version` match that exact current snapshot;
- the future twin's attack paths remain byte-for-byte identical to the supplied current baseline;
- every verified subject used by the graph still exists in the current twin with exactly the same node identity, kind, label and attributes.

If any represented change is unresolved, or attack paths have already drifted from the current baseline, analysis fails closed rather than returning a partial or mislabeled security interpretation.

## Output contract

The report records the exact current twin ID/version used as the baseline. Future twins persist that original baseline identity when they are derived, so a same-tenant but unrelated current snapshot cannot be substituted later merely because its attack paths happen to match.

Each item binds the analysis to:

- exact future CHANGE node;
- exact verified subject node;
- exact graph resolution ID;
- exact subject decision ID;
- exact materialization resolution ID;
- exact verified effect IDs and effect kinds;
- exact normalized risk directions;
- exact materialized capability IDs;
- existing attack-path IDs that already touch the verified subject;
- the evidence references consumed by the subject/effect state.

The report is immutable and JSON-serializable.

The report also carries `analysis_sha256`: a canonical SHA-256 over the exact tenant, current/future twin lineage, ChangeSet identity, ordered impact items, conservative impact labels and the fixed `not_evaluated`/`unresolved` boundary. A later transition stage can therefore bind itself to one exact reviewed analysis instead of accepting a semantically similar but different report.

`validate_future_attack_path_impact_report` is the required consumer gate for that handoff. It recomputes the canonical digest and fails closed if any bound identity, impact item, digest, completion flag, future-semantics boundary or security-verdict boundary has changed. Generation itself runs the same validator before returning a report.

## Conservative classifications

The report classifies only normalized verified risk directions:

| Verified directions | Impact label |
| --- | --- |
| increased | `potential_regression` |
| decreased | `potential_improvement` |
| increased + decreased | `mixed` |
| unchanged only | `unchanged` |

Path membership is computed from the current twin, never from a potentially mutated future path set.

These labels are not exploitability findings. They do not prove that a new path exists, that an old path is removed, or that a deployment is safe.

`security_verdict` therefore remains `not_evaluated` and `future_semantics` remains `unresolved`.

## Attack-path boundary

This slice only reports whether the verified subject already participates in existing attack paths. It does not:

- add attack steps;
- delete or rewrite attack paths;
- infer exploitability from `candidate_affects`;
- promote normalized effects into verified attack transitions;
- perform target interaction or network execution;
- widen authorization or use credentials.

Actual attack-path mutation belongs to a later independently verified stage.

## Verification

Regression coverage requires:

- increased / decreased / mixed / unchanged classification;
- deterministic existing-path reporting;
- empty path membership without a safety claim;
- complete graph resolution before analysis;
- live evidence revalidation;
- exact graph, subject-decision and materialization identity binding;
- cross-tenant rejection before ledger inspection;
- byte-for-byte read-only behavior for the input twin and its attack paths.
- fail-closed consumer validation for digest tampering and attempts to change `future_semantics` or `security_verdict`.
