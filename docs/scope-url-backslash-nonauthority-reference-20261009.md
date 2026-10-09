# Raw URL backslash nonauthority contract (offline reference)

**Scope:** authorization input validation before invoking any policy decision or executor. This PR adds a standalone Python stdlib reference with deterministic mocked policy calls; it does **not** change production authorization.

## Required behavior

1. Reject literal U+005C backslash anywhere in the raw URL (authority, userinfo, path, query, fragment, slash-like scheme separators) before parsing or normalization, and make **zero** downstream policy/executor calls.
2. Reject non-string untrusted objects without calling their conversion hooks.
3. A normal URL passing raw validation is only *eligible for downstream policy evaluation*, **not authorized**.
4. Percent-encoded `%5C` is not a literal raw backslash. Passing the raw guard does **not** settle decoded authority, scope, redirect, DNS, or transport semantics: these need separate downstream validation and pre-I/O decisions.
5. Security production owner must prove that a denial produces zero handler calls, zero evidence writes, and no scan requests, across all entry points.

## Proof / hold criteria

`python -m unittest discover -s tests -p 'test_scope_url_backslash_nonauthority_reference_20261009.py' -v`

Reference unit success by itself is **not** release proof. Keep draft until exact-head hosted Python 3.11/3.14 plus canonical permanent VPS CI succeed, producer grants (trusted issuer, tenant/client, engagement, asset, capability, revocation) are revalidated pre-I/O, and source-owner review confirms no bypasses. No real targets or grants are involved.
