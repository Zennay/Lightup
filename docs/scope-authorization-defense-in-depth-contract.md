# Scope authorization defense-in-depth contract

LightUp treats public active-target authorization as a chain of independent gates, not as a single boolean approval.

This regression package is deliberately tests/docs-only. It does not add target adapters, network activity, capability execution, authorization widening, remediation/retest execution, deployment, or attack-path mutation.

## Contract

For a public target to reach any future active execution path, every relevant boundary must still agree:

1. **Scope boundary** — unknown public targets fail closed; explicitly listed public targets still require current authorization.
2. **Activation boundary** — `PLAN_ONLY` never emits an execution permit, and `LAB_ONLY` cannot reinterpret a public target as an isolated lab.
3. **Execution-policy boundary** — target-active requests require a durable grant and remain bounded by the grant's asset, capability, and risk scope.
4. **Mode boundary** — passive-public and analysis-only requests cannot request active risk.
5. **Destructive boundary** — destructive risk never becomes target-active authority; it remains isolated-lab-only.
6. **Gate-independence boundary** — an activation permit never substitutes for the durable execution grant, a durable execution grant never substitutes for public scope authorization, and an explicit asset exclusion wins over an allowlist entry.

The dedicated regression module is `tests/test_scope_authorization_defense_in_depth.py`. It uses only in-memory objects and documentation-only hostnames; it performs no socket, HTTP, DNS, subprocess, tool, or target interaction.

## Collision boundary

This package intentionally does not modify the production files currently owned by parallel scope-authorization work, including scope, activation, execution policy, domain/state, web security, capability metadata, lab workers, coverage, planner argument binding, or evidence/remediation code.

The test contract may be restacked later if those production branches land, but it must continue to prove the same semantic invariant: no single approval artifact is sufficient to create public active-target authority. Scope acceptance, activation, and durable execution authorization are intentionally independent fail-closed requirements rather than interchangeable approval tokens.
