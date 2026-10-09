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

## Additional adversarial coverage\n\nThe isolated fixture also checks CR/LF/NUL-like spoofed header labels, loopback/private-address claim strings, hostile noniterable labels, time-window invalidity and preserving an immutable Target instance. Note that loopback is intentionally allowed by a separate local-only policy rule; it must never be inferred from transport headers.\n\n## Pure policy no-I/O coverage\n\nTwo additional tests assert that denied forged-host targets trigger no socket DNS resolution or connection functions, and that an unlisted target is rejected without inspecting a hostile authorization object. These mocks are scoped to the pure policy method only, not a proof about actual HTTP request handlers or adapters.\n\nAdditional reference tests cover no DNS/socket calls for an allowlisted host missing its grant, and preservation of bracketed IPv6 target identity despite a spoofed host hint. Both are synthetic, offline assertions only.\n\n## Unproven production requirements (HOLD)

These tests cover only the pure legacy `ScopePolicy.decide` surface. They do not pass an actual HTTP request through ingress or tool-dispatch, and a passing test does not prove trusted authorization. Source owner must verify a request carrying `X-Original-Host` cannot change any pre-I/O asset, tenant, engagement, capability, issuer, approval, time window, or revocation check. Both denied and revoked requests must produce **zero handler calls and zero evidence writes**, including across reverse proxies.

Maintain DRAFT/HOLD until production owner #107/#1128 completes end-to-end tests, explicit authorized customer consent is verified, and the exact PR head has passed both hosted Python 3.11/3.14 and permanent self-hosted VPS CI. No live targets, network requests, permissions, deployments or production-code edits were performed in this change.

## Configuration and repeated-label boundaries

The pure policy reference separately tests that `require_authorization_for_public=False` is an explicit trusted policy configuration, never a value inferred from `X-Original-Host`, and that 1/10/100 repeated spoofed labels cannot mutate configured allowlists. These tests are NOT an endorsement of disabling consent requirements in the production dispatcher.

## Alias and expiry isolation\n\nCase variants and underscore aliases of original-host routing metadata remain mere labels. A URL with an expired synthetic authorization remains denied even if a routing hint claims localhost. This offline legacy-policy reference is not a real ingress or tool-executor security proof.\n
## Header is not a network grant

A forged X-Original-Host naming an explicitly allowlisted IP cannot transfer authority to another public IP. Text strings such as `authorization=fixture` or `approved=true` embedded in a hint cannot replace a required authorization object. Both tests operate only on the pure offline policy; production trust provenance and pre-I/O enforcement are still pending.

## Domain and time-window boundaries

A synthetic grant with a forged original-host label must not authorize a different domain. `valid_from` and `valid_until` claims embedded in any hint are untrusted text and cannot create a missing authorization object. Source-owner production trust, revocation and pre-I/O enforcement remain separate requirements.

## Stable denial and provenance hint strings

0–256 repeated forged host labels must not modify normalized target identity or `OUT_OF_SCOPE` decisions. Owner, reference, issuer, revocation and capability strings embedded in a host hint are not an authorization record. These are offline policy-only regressions and not proof of persisted grant validation.

## Tenant, engagement and role claims

A routing hint string containing `tenant`, `engagement`, `asset`, `scope` or `role=admin` is never a trusted authorization or an allowlist override. The legacy-policy reference asserts only missing grant and unlisted host denials; production tenant/capability binding must be proven by #107/#1128.

## Capability and revoked-state hints

Forged `capability` values in original-host routing metadata cannot supply missing authorization. `revoked=false` in such metadata cannot restore an expired synthetic grant. This is offline legacy policy evidence only; persisted revocation enforcement requires the separate production owner integration.

## Operator approval and risk mode hints

An `operator_approved=true`, `approval_id`, `risk_level` or `mode=analysis_only` string inside routing metadata does not constitute an operator approval or a trusted scope grant. These offline tests do not claim that the production operator workflow is implemented.

## Loopback and mode isolation

A spoofed original-host claim for localhost, 127.0.0.1 or [::1] must not reclassify an unlisted HTTPS host as local. Claimed `plan_only`, `lab_only`, `active`, or `passive` strings also cannot replace an authorization grant for a publicly allowlisted URL. This is legacy pure-policy reference only.

## IPv6 approval and reference spoofing

A fake operator approval embedded in a routing label cannot grant a bracketed IPv6 target, and an asserted grant reference cannot transfer target identity to a different URL hostname. These synthetic reference cases do not prove trusted real-world issuer or approval provenance.

## Mapping-shaped header inputs

Additional offline regressions treat a mapping of claimed host/approval/reference header values as untrusted metadata, not a grant. A hostile mapping implementing raising dictionary accessors must not be inspected when an external target is denied. This is not a production HTTP ingress test and cannot prove trusted pre-dispatch authorization.

## Composite forged consent and hostile mapping

Tests assert a group of untrusted issuer/client/engagement/asset/capability/revocation hints cannot jointly create a grant, and that a hostile mapping cannot be inspected even for allowlisted hosts missing authorization. This still covers only the pure policy layer; true persisted consent is a separate production gate.

## Claimed lease / nonce / signature non-authority

An X-Original-Host label claiming lease_id, run_id, nonce or approval_signature is not a signed, trusted capability lease. Such text cannot fill a missing grant or permit an unlisted hostname even alongside synthetic Authorization. Production cryptographic provenance and pre-I/O enforcement remain separate gates.

## Signed consent hint isolation

A routing header claiming `consent_signed`, `authorization_verified`, `scope_hash`, or `approval_expires` does not create a trusted authorization object. Even a synthetic grant cannot transfer target identity through such claims. These are pure offline regressions, not real cryptographic verification or production dispatcher consent.

## Audit and evidence receipt non-authority

An untrusted routing label claiming audit_id, evidence_id, approval_record or signed_by cannot grant consent or override the scoped target identity. Audit evidence is not itself a verified capability grant. These synthetic cases only cover the legacy pure-policy boundary.

## Regression quality refinement (2026-10-09)

Replaced the prior permissive policy opt-out *allow* control with an explicit fail-closed before/after invariant. A forged `require_authorization_for_public=false` label must leave the restrictive policy setting unchanged and yield exactly `AUTHORIZATION_MISSING`, matching baseline. This does not assert that a permissive config is safe for production. The legacy policy also has no trusted persisted customer-consent provenance; all positive synthetic decisions remain untrusted and cannot enable I/O.

## Local lab configuration and allowlist immutability

IPv6 link-local targets remain out of scope when the trusted `allow_private_lab` setting is disabled, even when X-Original-Host labels claim to enable lab access. Similarly, forged `explicit_hosts` metadata cannot expand the configured hostname allowlist. Assert both denial reason and unchanged policy configuration. This evidence is for pure `ScopePolicy`, not the production dispatcher.

## Missing-grant network and HTTP dispatch tripwires

A new denied allowlisted URL case patches `socket.getaddrinfo`, `socket.create_connection` and `urllib.request.urlopen` and asserts none were called in pure `ScopePolicy.decide`. It confirms only that this pure function does not invoke those endpoints, **not** that a live API/worker dispatcher blocks target I/O; that requires the source-owner integration and corresponding real-handler instrumentation.

## Expired authorization transport tripwire

An already-expired synthetic authorization with `revoked=false` routing metadata must produce `AUTHORIZATION_EXPIRED` without calling `socket.getaddrinfo`, `socket.create_connection`, or `urllib.request.urlopen` from the pure scope decision. This is strictly a unit-layer assertion, not proof of production executor or evidence-write isolation.

## Future-dated grant transport tripwire

A not-yet-valid synthetic grant is denied with `AUTHORIZATION_EXPIRED` regardless of claimed approval expiry metadata. Pure policy evaluation must not invoke socket DNS, socket connection or urllib HTTP dispatch functions. This verifies only the unit boundary; production worker ingress and evidence-store write interception require separate integration tests.

## Invalid-target fail-closed and inspection order

Blank, whitespace-only and authority-less `https://` target values must return `INVALID_TARGET`, regardless of a forged `X-Original-Host` approval claim. With an invalid target, `ScopePolicy.decide` must not inspect an untrusted grant object or iterate untrusted labels. These checks are offline-only and deliberately avoid the DNS/configuration/real ingress paths owned by other scope PRs.

## Malformed target transport tripwire

An authority-less `https://` target with a forged approval label must fail with `INVALID_TARGET` without invoking DNS, socket connection, or urllib HTTP helpers from `ScopePolicy.decide`. This checks pure policy behavior only; production worker/evidence interception is still required.

## Out-of-scope check ordering and transport tripwire

An unlisted HTTPS hostname with a forged signed-consent routing label must be denied `OUT_OF_SCOPE` before reading a hostile synthetic authorization object. DNS, socket connection and urllib HTTP helpers must remain unused by this pure policy decision. Real worker dispatch and evidence store interception still require integration proof.

## Missing grant and hostile label collection

A public allowlisted URL without an Authorization must be denied `AUTHORIZATION_MISSING` without iterating, sizing, or coercing untrusted label objects. This is strictly a pure-policy ordering assertion; real ingress and trusted consent verification are separate owner responsibilities.

## Expired grant: hostile label non-inspection

With an allowlisted URL and expired synthetic Authorization, the pure scope policy must deny `AUTHORIZATION_EXPIRED` without iterating or coercing untrusted header labels. This is a unit-layer fail-closed invariant, not proof that production ingress, executor, or evidence store performs the corresponding gate.
