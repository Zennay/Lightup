# Revised-remediation direct-construction integrity

ST5 revised-remediation artifacts are planning records, not authority tokens.

The strict persisted handoffs already reject widened action flags, but callers can
also hold these dataclasses directly in memory. Therefore direct construction now
enforces the same non-executable stop line for:

- the remediation revision request;
- the revised remediation proposal;
- the revised review request;
- the final independent revised review.

Each artifact rejects forged code/config, tool, execution, target-interaction,
future-state-retest, deployment, or attack-path authority. Boolean/int confusion
such as `execution_allowed=0` is rejected as well; safety flags must be exact
booleans with their canonical value.

Lifecycle markers remain fixed. Future semantics stay `unresolved` and the
security verdict stays `not_evaluated`. The final review additionally requires
an actual `RemediationTextReviewDecision`, and `remediation_accepted` is true
only for `approved`.

This hardening changes no target interaction, execution policy, model behavior,
scope, deployment, remediation execution, retest behavior, or attack-path
mutation.
