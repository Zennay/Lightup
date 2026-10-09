# Sec-Fetch-Site is not an authorization grant

This isolated, offline reference contract ensures browser-supplied Fetch Metadata `Sec-Fetch-Site` is treated only as transport context. `same-origin`, `same-site`, `none`, `cross-site`, absent or hostile values cannot mint, recover, revoke or broaden a grant. The authorization decision must remain invariant under arbitrary changes to this header.

The synthetic predicate demands a verified, active grant and exact tenant, request, asset, capability, and generation bindings, with strict identity and revision types. It deliberately never reads, parses or coerces the untrusted header. The reference model is **not** production authorization enforcement or verified issuer provenance.

Offline checks (no targets or network): `python -m unittest discover -s tests -p test_scope_sec_fetch_site_nonauthority_reference.py -v`. Production ToolExecutor and activation code are untouched. This draft requires exact-head Python 3.11 and 3.14, permanent VPS CI, and scope-owner review before consideration for merge. Never use this reference to authorize active tests.
