# Scope authorization: Accept-Language is non-authoritative

## Boundary
The HTTP `Accept-Language` preference is caller-controlled presentation metadata. It is **never** an authenticated authorization claim, issuer proof, tenant selector, target permission, capability grant, risk approval, revocation override, or security-policy input. In particular `admin`, `approved`, language tags, q-values, and forged header lines cannot widen authority.

## Isolated reference
`tests/test_scope_accept_language_nonauthority_reference.py` contains nine pure-stdlib unit tests using a frozen synthetic grant and an inert predicate. It covers:
- canonical active/verified matching grants with arbitrary or malformed header values;
- denial on inactive or issuer-unverified grants;
- tenant, request, asset, and capability mismatches;
- rejection of subclassed identifier strings and non-boolean grant metadata;
- a hostile header object whose conversion/truthiness would raise, proving the predicate never consumes it;\n- forged grant objects and grant subclasses rejected **before** reading their attributes;\n- matching malformed grant/caller identifiers denied even when both sides agree on the same bad value.

This reference intentionally ignores the header rather than trying to sanitize it into an authority token. It is **not production enforcement** and its `issuer_verified` flag is merely a synthetic fixture, not a real issuer-verification mechanism.

## Ownership and safety
No source changes to `ExecutionPolicy`, `ToolExecutor`, ToolRegistry, the HTTP worker, grant issuance, token parsing, or real-target activation. Runtime source owner remains #107; nearby request label, User-Agent and media-type slices remain owned by their existing PRs. Production acceptance requires implementation-owner review and precise live-authorization tests at the actual dispatch boundary before any change can be considered enforced.

Offline execution: `python -m unittest discover -s tests -p 'test_scope_accept_language_nonauthority_reference.py' -v`.
No DNS, network, scans, handlers, target interaction, grant mutation, or deployment. Branch-only until shared permanent VPS CI capacity becomes available; no green CI evidence is claimed.
