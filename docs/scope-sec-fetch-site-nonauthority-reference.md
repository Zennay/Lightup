# Sec-Fetch-Site is not an authorization grant

This isolated, offline reference contract ensures browser-supplied Fetch Metadata `Sec-Fetch-Site` is treated only as transport context. `same-origin`, `same-site`, `none`, `cross-site`, absent or hostile values cannot mint, recover, revoke or broaden a grant. The authorization decision must remain invariant under arbitrary changes to this header.

The synthetic predicate demands a verified, active grant and exact tenant, request, asset, capability, and generation bindings, with strict identity and revision types. It deliberately never reads, parses or coerces the untrusted header. The reference model is **not** production authorization enforcement or verified issuer provenance.

Offline checks (no targets or network): `python -m unittest discover -s tests -p test_scope_sec_fetch_site_nonauthority_reference.py -v`. Production ToolExecutor and activation code are untouched. This draft requires exact-head Python 3.11 and 3.14, permanent VPS CI, and scope-owner review before consideration for merge. Never use this reference to authorize active tests.

Additional negative controls cover missing/extra binding keys, exact boolean typing for both grant flags, strict grant-side revision typing with revision-zero positive control, and rejected `str` subclasses on either binding side. These protect against representation/type confusion; they do not establish authorization provenance.

Further offline regressions exercise exact Grant typing (reject subclass), 128/129-character identity bounds on each binding, one-sided missing identities, and decision invariance across hostile browser-origin hints even when the grant revision differs. All examples use synthetic values only; no production authorization proof is implied.

The latest negative controls additionally ensure no iteration, length check, representation or comparison is performed on a hostile metadata object; grant/dispatch revision integer subclasses are rejected; and an immutable synthetic grant remains unchanged across transport-hint variants. These are offline reference checks only.
