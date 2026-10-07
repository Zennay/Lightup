# ScopePolicy terminal-dot identity acceptance

Tracking: #723  
Pinned parent: `main` at `1abc16a66fc490b1ba7272890dfbf498482fca9c`

## Contract

`ScopePolicy` may recognize one terminal DNS root dot as equivalent for a hostname, but malformed multiple-dot spellings must not inherit authority.

Required behavior:

- `example.test` and `example.test.` may remain equivalent for explicit-host membership.
- `localhost` and `localhost.` may retain the existing syntactic loopback behavior.
- `example.test..` must not match allowlisted `example.test`.
- an `explicit_hosts` entry `example.test..` must not authorize `example.test` or `example.test.`.
- `localhost..` must not collapse to `localhost` and receive loopback trust.
- scope decisions remain local string/IP parsing only; no DNS or target interaction is introduced.

## Expected RED on the pinned parent

Current `ScopePolicy.normalize_host()` returns `host.rstrip(".").lower()`, and explicit-host policy membership separately applies `item.rstrip(".").lower()`.

Because `rstrip(".")` removes all terminal dots:

- the malformed target `example.test..` currently becomes `example.test`;
- malformed policy entry `example.test..` currently becomes `example.test`;
- `localhost..` currently becomes `localhost`.

Those three acceptance methods are expected RED. The canonical single-root-dot explicit-host and localhost controls remain green.

## Distinction from adjacent ownership

- #117/#719 own durable `ScopeDefinition` terminal-dot canonicalization.
- #721 owns legacy `models.Authorization.assets` terminal-dot canonicalization.
- #286 owns exact/no-wildcard explicit-host membership.
- #367/#368 own decorated policy-entry syntax.
- active scope source owners retain `src/lightup/scope.py`; this branch changes no production source.

## Safety

Authorization narrowing only. No DNS/network I/O, target interaction, scanning, execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
