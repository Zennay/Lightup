# Redirect destination reauthorization: offline scope acceptance

## Invariant
An HTTP 3xx `Location` header is untrusted network response metadata. Authorization for an initial URL **must never** carry over automatically to a new hostname or IP address. Any future redirect-following adapter must resolve the next URL against the current URL **without making a request**, require a fresh `ScopePolicy.decide(Target(next_url, authorization=...))` decision and the stronger live dispatch-time grant/tenant/capability/risk gates, and deny before DNS, socket activity or handler dispatch if any gate fails. This must repeat for **every hop**, including retries. Cross-origin redirect headers never mint membership in the explicit host/IP allowlist.

## Reference acceptance
`PYTHONPATH=src python -m unittest tests.test_scope_redirect_reauthorization_reference -v`

Thirty-seven offline unittest methods now cover a future-dated destination grant, loss of authorization between two individually allowlisted hops, an unrelated grant that cannot create membership for an unlisted host, a mixed-case unknown hostname, future-dated and expired IP grants, fail-stop behavior for expiration mid-chain, out-of-scope public IPv6, explicit IPv6 allowlist grant controls and encoded path confusion; positive controls for case/trailing-dot normalization and an explicitly permitted IP; exact-CIDR boundary, lab-to-public redirects, empty destination denial, custom-port grant checks and unknown-host scheme downgrade rejection, plus `urljoin` resolution of relative redirects, network-path (`//host`) redirects, absolute custom-port redirects, early termination on the first denied hop, and query/fragment distractions on out-of-scope destinations. Each hop must independently revalidate a currently valid grant (not necessarily mint a new grant); an initial allow does not imply authorization of any subsequent hop.

The tests exercise the actual legacy `ScopePolicy.decide` in memory: allowed initial hostname, unknown host or IP redirect, allowlisted IP requiring authorization, expired and missing grants, userinfo spoofing, custom port, authorization-disabled but out-of-scope target, and a three-hop chain that stops on an unknown destination.

## Confirmed policy gaps: scheme and port

Three characterization tests show that legacy `ScopePolicy.decide` accepts an `https` to `http` transition, a same-host port change and an unsupported `ftp` scheme when the hostname and synthetic grant remain valid. **An allowed legacy scope result must NOT be interpreted as approval to make the redirected request.** The production redirect adapter must additionally enforce an explicitly allowed scheme and port (and any no-downgrade rule), trusted destination binding, current issuer-verified grant, tenant/capability/risk constraints, and a fresh pre-I/O gate at every hop. The tests document currently missing enforcement rather than asserting safety.

## Ownership and limitations
This branch adds only a dedicated test and this document. It **does not implement** a redirect-following HTTP adapter or a production per-hop gate. The synthetic `Authorization` fixture is not verified consent (no signature, tenant binding, capability binding or runtime re-resolution). Current active public-target interaction stays OFF. No DNS, network, scanners, tests against external targets, production file edits, approvals or deployment. Source owner must integrate an actual pre-I/O redirect gate and verify exact-head CI and permanent VPS tests before treating this reference as enforcement.
