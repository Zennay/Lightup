# Retry-After transport metadata is not authorization

## Contract
HTTP `Retry-After` (delta-seconds or HTTP-date), whether presented by a server,
gateway, cache, proxy, client or operator, is a **scheduling hint only**. It must
never create, extend, renew, restore, revoke or override consent; change the
authorized tenant/request/asset/capability; adjust an authorization revision;
or bypass live revocation, risk elevation and the operator activation gate.

A response code (including 200, 202, 429 and 503) paired with Retry-After
does not establish an authenticated issuer, authorization grant, target scope
or permission to retry a capability. Backoff completion is not approval.
On every retry, production must independently revalidate issuer-owned grant
provenance, signed/recorded consent, live scope, tenant and request binding,
capability, time validity, revision, revocation, risk and activation **at dispatch**.
Expired, missing or unverifiable evidence fails closed, even if Retry-After is 0.

## Isolation / acceptance
This change is an independent **offline synthetic reference**, not enforcement.
The positive fixture proves only internal consistency; it does not prove issuer
authentication or grant legitimacy. No production executor, grant issuance,
credential material, network, DNS, target IO, scanner or capability invocation
is changed or enabled. Real-target execution remains OFF.

Run `python -m unittest discover -s tests -p 'test_scope_retry_after_nonauthority_reference.py' -v`
on hosted Python 3.11/3.14 and canonical permanent VPS against the exact PR
head. Keep draft pending those checks and production scope-owner review.
