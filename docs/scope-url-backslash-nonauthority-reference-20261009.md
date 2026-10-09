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

## Parser-order regression (latest addition)

The offline suite uses a poisoned `urlsplit` mock to prove literal backslashes and hostile non-string inputs are rejected **before** any URL parser call or policy callback. This prevents parser-dependent normalization from laundering malformed raw input into a seemingly trustworthy URL. Parser-order tests remain references only; source-owner integration must demonstrate the same pre-I/O order for actual producer entry points.

## Full-boundary poisoned-parser proof — 2026-10-09

The test suite now covers every insertion offset of U+005C in a synthetic URL while simultaneously poisoning `urlsplit` and the downstream policy. None may be called for rejected raw input. An authority backslash+userinfo ambiguity is also rejected regardless of any mocked parser return value. These are deliberately **offline ordering proofs only**, not live issuer, consent, revocation, redirect or executor authorization.

Security release gates remain: exact-head hosted Python 3.11/3.14; canonical permanent VPS CI; source-owner integration demonstrating zero real executor/evidence calls; approval of trusted grants before active I/O. Do not grant, merge or deploy based on this document.
