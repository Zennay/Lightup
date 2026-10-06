# Target labels are non-authoritative scope metadata

Issue: #293

## Security invariant

`Target.labels` are descriptive metadata only. They are not part of the scope identity and must never mint, widen, downgrade, or replace authorization.

Scope authority is derived from the normalized target identity plus the explicit scope policy and, for public explicit-host/network paths, the current authorization object. A label that happens to contain words such as `lab`, `private_lab`, `authorized`, `localhost`, an authorization reference, an allowlisted hostname, or a CIDR is untrusted text and has no authorization effect.

## Regression contract

The dedicated regression module proves that:

- labels cannot turn an unknown hostname into allowed scope;
- labels cannot satisfy the authorization requirement for an explicit public host;
- labels cannot satisfy the authorization requirement for an explicit public network;
- loopback classification is determined by the normalized target itself, not by labels;
- the scope decision implementation does not read `Target.labels`.

The last check is intentionally structural. If a future scope refactor begins consuming labels, that change must fail this contract and receive an explicit security review rather than silently creating a second authorization channel.

## Collision and safety boundary

This slice adds tests and documentation only. It does not modify `scope.py`, models, activation, execution policy, domain persistence, orchestration, the webapp, workers, or evidence-remediation code.

All regression cases are in-memory and offline. They perform no DNS resolution, socket or HTTP I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment, or attack-path mutation.
