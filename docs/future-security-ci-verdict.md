# ST5 CI security verdict policy

This package is the first Security Twin ST5 boundary. It converts completed,
live-revalidated ST4 output into deterministic CI decision metadata.

It still does **not** merge, deploy, approve a deployment, interact with a
target, mutate an attack path, widen authorization, or use credentials.

## Inputs

The verdict consumes the exact:

- ST4 `FutureAttackPathSecurityDeltaReport`;
- ST4 `FutureAttackPathGraphDiffPolicyDecision`;
- graph-diff preview;
- transition proposal and resolutions;
- immutable run contexts;
- live evidence/state store;
- customer CI verdict policy.

Both ST4 artifacts are rebuilt from live lineage before the supplied serialized
objects are trusted. Stale, tampered, cross-tenant or lineage-drifted handoffs
therefore fail closed.

## Verdict vocabulary

The only verdicts are:

- `PASS`
- `PASS_WITH_WARNING`
- `REVIEW_REQUIRED`
- `BLOCK`

Evidence-complete `introduced`, `worsened`, `improved`, and `removed`
classifications are policy-configurable. The strict default blocks introduced
or worsened attack paths and passes improved or removed paths.

`insufficient_evidence` is different: it is hard-mapped to at least
`REVIEW_REQUIRED` and can never be converted into PASS by customer policy.
When multiple delta items exist, the most severe resulting verdict wins.

The decision also exposes a CI conclusion mapping:

- PASS -> `success`
- PASS_WITH_WARNING -> `neutral`
- REVIEW_REQUIRED -> `action_required`
- BLOCK -> `failure`

Publishing that conclusion to GitHub Checks is a separate ST5 package.

## Deterministic evidence binding

The canonical verdict digest binds:

- tenant and current/future twin lineage;
- ChangeSet, proposal, impact-analysis and preview digests;
- ST4 report and graph-diff policy decision digests;
- policy identity, version and complete classification mapping;
- final verdict and CI conclusion;
- reason codes;
- contributing classifications;
- evidence and capability IDs;
- fixed non-mutation/non-authorization boundaries.

A policy change therefore changes the policy digest and verdict digest even
when the underlying ST4 evidence is unchanged.

## Safety boundary

A `PASS` means only that the configured CI security policy evaluated the
currently proven ST4 delta as PASS.

It explicitly does **not** mean deploy permission:

- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`

No target interaction, network execution, credential use, exploit execution,
authorization widening, attack-path mutation, merge action, or deployment
action is implemented by this package.
