# Future remediation text proposal

This ST5 slice is the first model-producing step in the evidence-remediation
lane. It consumes an exact live-valid remediation authoring request and asks
the configured `remediation_advisor` role for defensive prose.

## Boundary

The proposal is planning output only. Before model invocation the implementation
rebuilds and compares the complete live request lineage through the existing
authoring-request validator. Any evidence, plan, report, transition, context or
state drift therefore fails before the model is called.

The model receives only bounded request metadata:

- request and bundle digests;
- change/subject/resolution identifiers;
- introduced/worsened classification;
- attack-path, effect and capability identifiers;
- evidence identifiers, run/capability IDs, kinds and SHA-256 digests.

It does **not** receive persisted evidence `source`, arbitrary evidence
`metadata`, credentials, authorization references, target arguments or raw
payload bytes through this contract.

## Model contract

The existing provider-neutral `ModelGateway` is used with
`ModelRole.REMEDIATION_ADVISOR`. No provider-specific behavior is added. The
system prompt treats all request fields as untrusted data and requires
defensive prose only, with no claims that remediation was applied, tested,
verified, deployed or authorized.

The response is accepted only when:

- the response role remains `remediation_advisor`;
- the response model identity matches the configured role binding;
- content is non-empty, NUL-free and within the bounded character limit.

The immutable proposal records provider/model provenance, the exact request and
bundle digests, a content SHA-256 and a canonical proposal SHA-256.

## Authority stop line

Creating text changes exactly one semantic flag:
`remediation_proposal_created=true`.

All of the following remain false:

- `code_change_authorized`;
- `tool_call_created`;
- `execution_allowed`;
- `target_interaction_allowed`;
- `future_state_retest_allowed`;
- `deployment_authorized`;
- `attack_path_mutation_allowed`.

`future_semantics` remains `unresolved` and `security_verdict` remains
`not_evaluated`.

This module cannot apply a remediation, generate an executable tool action,
contact a target, retest the future state, deploy a change, or mutate the
security twin. Those require separate later contracts and authorization.
