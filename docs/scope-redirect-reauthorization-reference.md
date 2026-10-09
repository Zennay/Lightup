# Redirect destination reauthorization: offline scope acceptance

## Invariant
An HTTP 3xx `Location` header is untrusted network response metadata. Authorization for an initial URL **must never** carry over automatically to a new hostname or IP address. Any future redirect-following adapter must resolve the next URL **without making a request**, require a fresh `ScopePolicy.decide(Target(next_url, authorization=...))` decision and the stronger live dispatch-time grant/tenant/capability/risk gates, and deny before DNS, socket activity or handler dispatch if any gate fails. This must repeat for **every hop**, including retries. Cross-origin redirect headers never mint membership in the explicit host/IP allowlist.

## Reference acceptance
`PYTHONPATH=src python -m unittest tests.test_scope_redirect_reauthorization_reference -v`

Twelve offline unittest methods now cover a future-dated destination grant, loss of authorization between two individually allowlisted hops, and an unrelated grant that cannot create membership for an unlisted host. Each hop must receive an independently current grant; an initial allow does not imply authorization of any subsequent hop.\n\nThe tests exercise the actual legacy `ScopePolicy.decide` in memory: allowed initial hostname, unknown host or IP redirect, allowlisted IP requiring authorization, expired and missing grants, userinfo spoofing, custom port, authorization-disabled but out-of-scope target, and a three-hop chain that stops on an unknown destination.

## Ownership and limitations
This branch adds only a dedicated test and this document. It **does not implement** a redirect-following HTTP adapter or a production per-hop gate. The synthetic `Authorization` fixture is not verified consent (no signature, tenant binding, capability binding or runtime re-resolution). Current active public-target interaction stays OFF. No DNS, network, scanners, tests against external targets, production file edits, approvals or deployment. Source owner must integrate an actual pre-I/O redirect gate and verify exact-head CI and permanent VPS tests before treating this reference as enforcement.
