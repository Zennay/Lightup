# Scope hostname selectors — offline conservative reference (2026-10-08)

This independent scope-authorization slice specifies **literal hostname selector equality only**. It intentionally does **not** enable any real-target assessment or implement production approval.

## Trust boundary

A stored scope selector is not itself evidence of consent. Production authorization still requires authenticated tenant and engagement identity, an operator-approved immutable grant, exact asset/capability/risk binding, valid time window, current revocation state, and durable pre-dispatch audit. Deny when any dependency is missing or unavailable.

The reference accepts lower-case ASCII DNS-form names of two or more labels, bounded to 253 characters and 63 characters per label. It refuses case conversion, trailing-dot rewriting, suffix inclusion, wildcard expansion, URL/port/userinfo forms, Unicode, IP literals and malformed labels. An IDNA A-label may be syntactically valid but is **not verified as owned or approved**. The production owner must apply its own policy for IDNA, public suffixes and domain ownership. No DNS lookups are made.

A grant for `api.example.test` does **not** cover `child.api.example.test`, `api.example.test.evil.test` or `*.example.test`. If future explicit subdomain support is desired, it must receive separate consent, an approved policy with bounded expansion, and independent release review. Do not infer wildcards from certificate SANs, DNS CNAME chains, redirects or hostname suffixes.

## Reproduction and limitations

Run locally/offline: `python -m unittest discover -s tests -p 'test_scope_hostname_wildcard_boundary_reference_20261008.py' -v`.

This test file deliberately uses only the Python standard library and synthetic strings. It is **not** integrated into the production executor, grant store or request parsing. Passing these cases does not prove authorization, control of a domain, time-of-check safety, DNS rebinding resistance, or real-world scanning safety.

Parallel ownership: no existing source, domain, executor, scope or test files modified. Keep this as a draft/reference until the production scope owner reviews the contract and exact-head hosted + canonical permanent-VPS CI evidence is available. No network, targets, capability dispatch, deployment, or permission widening.
