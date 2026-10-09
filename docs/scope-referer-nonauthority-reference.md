# HTTP Referer non-authority — isolated scope reference

**Status:** offline synthetic acceptance contract only; not production enforcement.

HTTP `Referer` is caller-controlled navigation metadata. Neither a trusted-looking
origin/path nor absence/presence/formatting of that header may issue, revive, elevate
or transfer target authorization. This contract is independent of URL parsing,
CSRF/session gates, UI display and audit-correlation behavior.

## Invariants

1. Live verified issuer approval, active grant and exact tenant/request/asset/capability binding remain necessary.
2. Spoofed approval URLs, header injection-looking text, object metadata, and malformed Referer values cannot supply missing authority.
3. Changing Referer alone never changes the synthetic decision when all authorization fields stay fixed.
4. Both matching and mismatching malformed identity values fail closed, including empty strings, embedded C0/DEL controls and non-string identities; annotation-compatible but noncanonical booleans do not count as approval.\n5. Exact built-in envelope and identity types are required: caller-controlled subclasses cannot override equality or authority checks.\n6. Mutating transport label containers leaves grant and call identities unchanged.
7. A Referer URL never becomes an implicitly authorized active destination.

## Offline proof

Run `python -m unittest discover -s tests -p 'test_scope_referer_nonauthority_reference.py' -v`.
This exercises ten pure-stdlib unittest methods, including matching-invalid grant/call fields, polymorphic identities, envelope subclasses and transport-label mutation and hostile Referer protocol objects, with no network, DNS, handler or target side effects.

## Production gate / collision rules

The decision oracle in the test intentionally does **not** import the production
executor; it does not prove authorization is enforced at dispatch. Production
`ToolExecutor` ownership remains #107, including live grant re-resolution and
destination binding. Promote only after source-owner integration and exact-head
Python 3.11/3.14 hosted plus canonical permanent VPS CI proof. Keep target
activation disabled. This branch changes tests/docs only.
