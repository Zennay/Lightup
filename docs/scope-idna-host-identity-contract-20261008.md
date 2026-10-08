# Scope authorization: internationalized-host identity (RED acceptance)

## Observed gap on main

`ScopePolicy.normalize_host` lowercases the parsed host but does not define IDNA canonicalization or a Unicode-host rejection rule. An explicitly allowlisted internationalized name represented as an A-label (`xn--bcher-kva.example.test`) does not match the corresponding U-label (`bücher.example.test`), and vice versa. Silent mismatch complicates tenant authorization review and makes written scope ambiguous.

## Contract

Choose one policy centrally, before host allowlist matching: either (1) reject all noncanonical Unicode hostnames as `INVALID_TARGET`, with a documented ASCII-only allowlist rule; or (2) convert both target hostnames and configured host allowlists to IDNA A-labels using a deliberate, strict canonicalization function. Reject invalid or ambiguous encodings. Preserve exact host equality, expiry, and grant restrictions; canonicalization must never create implicit wildcards or additional authority. This fixture does not itself prove admission is safe.

## Isolation and verification

Only adds `tests/test_scope_idna_host_identity_red_20261008.py` and this document. Does not modify `src/lightup/scope.py`, domain grants, executor, discovery or live targets; scope/source owner must choose and implement production behavior. Execute offline with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_idna_host_identity_red_20261008.py' -v` and capture expected RED on current main. Once implemented, rerun targeted plus full regression on pinned CI/VPS SHA. Do not promote until green. Literal `.example.test` values are documentation-only, with no network access.
