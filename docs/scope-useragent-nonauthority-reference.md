# Scope authorization: User-Agent non-authority (offline reference)

## Boundary
Transport `User-Agent` and similar client identity labels are untrusted diagnostics. They must never be parsed as an operator approval, issuer signature, allowlist entry, tenant identity, target identity, capability grant or scope revision.

This additive test pack is a **standalone synthetic reference predicate**, not enforcement in LightUp production. In particular, its `issuer_verified=True` fixture is not a cryptographic verification. No real target or network capability is activated.

## Expected contract
1. Current, issuer-authenticated grant, tenant, request, asset and capability bindings are independent gates.
2. Spoofed `User-Agent` values such as `Admin-Authorized/yes`, arbitrary Unicode, controls and oversized strings cannot create, renew, elevate or recover authorization.
3. Client labels are *neither positive nor negative authority*: changing only the label does not flip a scope decision.
4. Malformed or polymorphic grant/request envelopes, exact-string identity field subclasses, control characters and truthy pseudo-booleans are rejected in the synthetic reference. Every one of the four identity fields receives matching-invalid and polymorphic-input regression coverage.
5. Control-character fixtures contain real Python escapes (CR/LF, tab and DEL), not escaped literal backslash sequences.
6. Denials precede dispatch, network access, evidence writes and retries. Queued work must re-resolve current authorization before each dispatch.

## Acceptance and ownership
Run `python -m unittest tests/test_scope_useragent_nonauthority_reference.py` on hosted Python 3.11 and 3.14 and the canonical permanent VPS runner at the **exact proposed head**. The pure-stdlib tests make no sockets, DNS, target requests, credential reads or dispatch calls.

No production source is modified. Production executor ownership stays with PR #107; trusted issuer provenance, revocation and risk/window checks require source-owner implementation and review. Do not merge or activate TARGET_ACTIVE based on this synthetic pack alone.
