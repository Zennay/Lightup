# Scope authorization membership non-authority contract

LightUp treats authorization and scope membership as separate fail-closed questions.

A legacy `Authorization` may be evaluated only after a target has independently matched declared public scope. Merely attaching an authorization object must never create host/network membership, rescue malformed target identity, or reinterpret an undeclared public target as allowed scope.

## Contract

The dedicated regression proves:

- a current authorization cannot turn an undeclared public hostname into `EXPLICIT_HOST`;
- a current authorization cannot turn an address outside every declared CIDR into `EXPLICIT_NETWORK`;
- setting `require_authorization_for_public=False` removes only the authorization check for already-declared public membership; it does not create membership;
- an invalid/empty target remains `INVALID_TARGET` even when authorization is attached.

The invariant intentionally does **not** prescribe what fields make an authorization sufficient after membership is established. That positive authorization contract is owned by the active #100 legacy-target-binding/revocation lane, which adds exact asset binding and related provenance checks.

The precedence remains:

`normalize target -> establish membership -> apply the current public authorization contract -> allow or deny`

never:

`authorization present -> create membership`.

## Boundary

This is a tests/docs-only invariant on top of exact current `main` `1abc16a66fc490b1ba7272890dfbf498482fca9c`.

It intentionally does not modify or claim ownership of:

- `src/lightup/scope.py` or `src/lightup/models.py`;
- the active revocation / legacy-target-binding work in #100;
- the cross-gate scope/activation/execution composition in #262/#264;
- exclusion precedence (#343/#345), decision purity (#344), policy monotonicity (#346), durable time-window (#347), revocation precedence (#348), decision immutability (#349), or capability metadata (#178).

## Safety

The proof is pure in-memory policy evaluation. It performs no DNS lookup, socket/HTTP request, target interaction, scanning, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation. It only prevents authorization from being interpreted as scope membership.
