# Target labels are non-authoritative

Issue: #293

## Contract

`Target.labels` is descriptive metadata only. Scope authority must come from the normalized target identity, explicit scope configuration, and the required current authorization object.

The regression contract proves that:

- authority-like labels such as `lab`, `private_lab`, `authorized`, `localhost`, or an allowlisted hostname do not allow an otherwise unknown public hostname;
- labels cannot replace the current-authorization requirement for an explicitly allowlisted public hostname;
- labels cannot replace the current-authorization requirement for an explicitly allowlisted public network;
- loopback classification follows the normalized target value rather than any label value;
- a static AST guard keeps `src/lightup/scope.py` free of `*.labels` reads, so future refactors cannot quietly turn descriptive labels into scope authority.

## Collision boundary

This slice changes only its dedicated regression module and this document. It does not modify `src/lightup/scope.py`, models, activation, execution policy, domain, orchestration, webapp, existing scope tests, or any evidence-remediation code.

## Safety

The proof is offline and in-memory only. It performs no DNS, socket, HTTP, target interaction, scanning, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation. It only locks in an existing fail-closed scope-authorization boundary.
