# Remediation authoring/review direct-construction integrity

The original ST5 remediation-text authoring and review chain is planning-only.
Its strict persisted handoffs already reject tampered authority fields; direct
in-memory construction now enforces the same stop line.

The guarded top-level artifacts are:

- remediation authoring request;
- remediation text proposal;
- independent review request;
- independent review result.

Lifecycle markers must keep their canonical values. Every code/config, tool,
execution, target-interaction, future-state-retest, deployment, and attack-path
authority field must be exact `False`; integer lookalikes such as
`execution_allowed=0` are rejected. Future semantics remain `unresolved` and
the security verdict remains `not_evaluated`.

The final review additionally requires an actual
`RemediationTextReviewDecision`. `remediation_accepted` is true only when the
decision is `approved`.

This is an integrity-narrowing change only. It adds no model, target, execution,
remediation, retest, deployment, future-state resolution, or attack-path
behavior.
