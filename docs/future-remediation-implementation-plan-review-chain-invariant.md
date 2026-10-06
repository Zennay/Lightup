# ST5 implementation-plan review chain invariant

Issue #287 adds a tests/docs-only safety invariant on top of the strict persisted implementation-plan review handoff from #283.

## Contract

An implementation-plan review is still planning metadata. A successful independent review may record:

- `implementation_plan_review_completed = true`;
- `implementation_plan_accepted = true`.

That acceptance is **not** action authority. The review must keep every action-bearing flag exactly false:

- `code_change_authorized`;
- `tool_call_created`;
- `execution_allowed`;
- `target_interaction_allowed`;
- `future_state_retest_allowed`;
- `deployment_authorized`;
- `attack_path_mutation_allowed`.

The artifact also remains `future_semantics = "unresolved"` and `security_verdict = "not_evaluated"`.

## Regression coverage

`tests/test_future_remediation_implementation_plan_review_chain_invariant.py` proves that:

1. an approved review advances acceptance only;
2. revision-required and insufficient-evidence outcomes remain non-executable;
3. producing and strictly reloading a review does not mutate the upstream planning request, remediation review, review request, or implementation plan;
4. the persisted review carries no command, patch, code, tool-argument, target-argument, credential, deployment-plan, retest-result, or positive security-verdict payload surface;
5. the acceptance boolean cannot be reused as a proxy for any action-authority flag;\n6. implementation-plan content stays in the verifier's untrusted user-data channel while the system message explicitly forbids tools, code/patch/command generation, retesting, deployment and security-verdict creation.

## Boundary

This slice changes no production source and does not modify #278/#280/#281/#283-owned files. It does not invoke targets, execute remediation, create code changes, run tools against customer assets, authorize retesting or deployment, resolve future state, issue a security verdict, or mutate attack paths.

Any future implementation/execution stage must introduce a separate explicit authority boundary and must not derive authority from `implementation_plan_accepted` alone.
