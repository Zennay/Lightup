# Future Security ST6: isolated future-state retest request

ST6 turns a live-revalidated, **evidence-complete** ST5 remediation/retest plan
into an immutable request for an isolated future-state retest.

## Rules

- The plan is rebuilt from the exact ST4 report, graph-diff preview, transition
  proposal, resolutions, run contexts and live state store. Drift, tampering or
  a cross-tenant mix fails closed.
- A plan with any `insufficient_evidence` item is refused: collect evidence
  first, then rebuild the plan.
- One request item exists per retest-required plan item.
  `blocked_on_remediation` is true for `introduced` / `worsened` items, which
  need a remediation before the retest may be scheduled; `improved` / `removed`
  items are verification retests and are not blocked.
- The request digest binds the full lineage including the ST5 `plan_sha256`.

## Safety boundary

A request is **not** an authorization. It always carries:

- `isolated_environment_required`, `scope_gate_required`,
  `authorization_gate_required`, `tool_policy_gate_required` = true
- `real_target_interaction_allowed`, `execution_allowed`,
  `deployment_authorized`, `attack_path_mutation_allowed` = false
- `future_semantics = "unresolved"`, `security_verdict = "not_evaluated"`

No retest is executed here. A later package must pass the request through the
scope, authorization and tool-policy gates before anything runs.
