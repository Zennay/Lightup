# Legacy authorization is non-authoritative for lab classification

LightUp keeps the public-authorization gate separate from loopback/private-lab classification.

Attaching a legacy `Authorization` object to a target must not make that object an input to lab classification. Loopback membership and explicitly enabled private-lab membership are derived from normalized target identity plus lab policy. Public authorization metadata cannot upgrade, downgrade, or otherwise steer those decisions.

## Contract

The dedicated regression proves:

- loopback remains `LOOPBACK` with no, current, future, or expired legacy Authorization attached;
- `localhost` remains a syntactic loopback decision even with expired authorization;
- an ordinary private target remains `PRIVATE_LAB` when `allow_private_lab=True`, independent of authorization state;
- a current Authorization cannot bypass `allow_private_lab=False`: private and link-local targets remain `OUT_OF_SCOPE`.

The invariant deliberately does **not** define link-local/reserved/multicast/unspecified addresses as positive private-lab members. The active #100 hardening lane owns that classification narrowing and excludes those special ranges from the private-lab shortcut.

The precedence is therefore:

`normalize identity -> apply lab identity/policy classification -> public membership/auth checks`

Legacy public authorization is not a lab-classification signal.

## Boundary

This is a tests/docs-only invariant on exact current `main` `1abc16a66fc490b1ba7272890dfbf498482fca9c`.

It does not modify or claim ownership of `scope.py`, `models.py`, activation, execution-policy, labeval/labsync, network workers, domain/state, webapp, or existing scope-authorization sibling work.

It is separate from #364: #364 proves Authorization cannot mint undeclared public membership; this contract proves Authorization cannot steer lab classification or bypass the explicit private-lab switch.

## Safety

Pure in-memory classification proof only. No DNS lookup, sockets/HTTP, target interaction, scanning, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
