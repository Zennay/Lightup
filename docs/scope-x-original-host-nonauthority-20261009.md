# X-Original-Host is not authorization evidence (offline reference)

## Threat boundary

An incoming `X-Original-Host` HTTP header is client-controlled or proxy-controlled routing metadata. It is not proof of ownership, consent, an operator approval, or the asset identity bound to an authorization grant. A forged header naming an approved asset must not enable an assessment of a different target.

## Covered reference contracts

- ScopePolicy evaluates `Target.value`, not attacker-provided header-like labels.
- Unknown external host stays `OUT_OF_SCOPE` even when a label claims the allowlisted host.
- An allowlisted host without a grant stays `AUTHORIZATION_MISSING`.
- A synthetic in-memory Authorization cannot allow an *unlisted* host.
- The effective hostname comes from the target URL authority, not a forwarding hint.
- Changing the hint does not rewrite the host of an otherwise accepted synthetic reference target.

Command: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_x_original_host_nonauthority_20261009.py' -v`.

## Additional adversarial coverage\n\nThe isolated fixture also checks CR/LF/NUL-like spoofed header labels, loopback/private-address claim strings, hostile noniterable labels, time-window invalidity and preserving an immutable Target instance. Note that loopback is intentionally allowed by a separate local-only policy rule; it must never be inferred from transport headers.\n\n## Pure policy no-I/O coverage\n\nTwo additional tests assert that denied forged-host targets trigger no socket DNS resolution or connection functions, and that an unlisted target is rejected without inspecting a hostile authorization object. These mocks are scoped to the pure policy method only, not a proof about actual HTTP request handlers or adapters.\n\n## Unproven production requirements (HOLD)

These tests cover only the pure legacy `ScopePolicy.decide` surface. They do not pass an actual HTTP request through ingress or tool-dispatch, and a passing test does not prove trusted authorization. Source owner must verify a request carrying `X-Original-Host` cannot change any pre-I/O asset, tenant, engagement, capability, issuer, approval, time window, or revocation check. Both denied and revoked requests must produce **zero handler calls and zero evidence writes**, including across reverse proxies.

Maintain DRAFT/HOLD until production owner #107/#1128 completes end-to-end tests, explicit authorized customer consent is verified, and the exact PR head has passed both hosted Python 3.11/3.14 and permanent self-hosted VPS CI. No live targets, network requests, permissions, deployments or production-code edits were performed in this change.
