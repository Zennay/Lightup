# ST5 remediation and future-state retest plan

This package advances the remediation/retest branch of Security Twin ST5
without waiting for CI-verdict publication.

It consumes a completed ST4 security delta report but does not trust serialized
ST4 output by itself. The report is rebuilt from the exact graph-diff preview,
transition proposal, verified resolutions, immutable run contexts and live
evidence/state store. Drift or tampering fails closed before a plan exists.

## Deterministic follow-up mapping

The first package deliberately plans **what must happen next** instead of
inventing a concrete security fix without enough domain context.

- `introduced` -> remediation required, then future-state retest required
- `worsened` -> remediation required, then future-state retest required
- `improved` -> verification retest required before accepting the improvement
- `removed` -> verification retest required before accepting the removal
- `insufficient_evidence` -> collect more evidence first; no clean/remediated
  claim and no executable retest plan yet

Every item preserves the exact change, subject, transition resolution,
graph-diff action, current attack-path, effect, evidence and capability lineage.

The canonical plan digest binds that lineage plus the ST4 report digest and the
derived remediation/retest requirements. Replay from unchanged evidence is
deterministic.

## Safety boundary

This is planning metadata only:

- `execution_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

No target interaction, exploit execution, credential use, authorization
widening, code/config mutation, GitHub merge, deployment, or automatic retest
execution is implemented here.

A later package may turn an evidence-complete plan into an isolated future-state
retest request, but that request must pass its own scope/authorization/tool
policy gates before any execution.
