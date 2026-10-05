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
- the future twin's attack paths remain byte-for-byte identical to the supplied current baseline.

If any represented change is unresolved, or attack paths have already drifted from the current baseline, analysis fails closed rather than returning a partial or mislabeled security interpretation.

## Output contract

The report records the exact current twin ID/version used as the baseline.

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

## Conservative classifications

The report classifies only normalized verified risk directions:

| Verified directions | Impact label |
| --- | --- |
| increased | `potential_regression` |
| decreased | `potential_improvement` |
| increased + decreased | `mixed` |
| unchanged only | `unchanged` |

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
