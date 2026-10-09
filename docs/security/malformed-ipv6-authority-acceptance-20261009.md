# Malformed IPv6 authority — source-owner acceptance gate (2026-10-09)

Owner: scope/authorization production integration (#107, #1128).
Regression PR: #1131 (draft). These are **synthetic offline** URLs, never customer-authorized targets.

## Gap
`ScopePolicy.normalize_host` calls `urllib.parse.urlparse` without catching
`ValueError`. The Python parser raises on unbalanced `[` or `]` in URL
authorities. `ScopePolicy.decide` therefore can raise rather than return a
structured denial. This is not approval to execute target work.

## Required contract
1. Reject raw whitespace, Unicode control/format/surrogate characters before URL parsing; these must cause zero policy or handler calls. This offline reference is not wired to production and does not replace the trusted pre-I/O check. Catch invalid authority/parser failures at the normalization boundary across URL schemes; malformed authority syntax must never reach a scope policy or executor. Bracketed authorities must contain a syntactically valid IPv6 literal (or supported IP literal form), never a hostname or IPv4 address disguised as bracketed IPv6.
2. Require a nonempty parsed authority and hostname before policy delegation; missing-host URLs must cause zero policy and handler calls. URL syntax validity alone never constitutes consent. Force urllib.parse's lazily evaluated hostname and port properties before policy delegation, rejecting nonnumeric, negative, empty explicit (`host:`), or out-of-range ports without policy/handler calls. Deny malformed URLs with `allowed=False`, `reason=INVALID_TARGET`, and
   `normalized_host=None`.
3. Test denial as the complete structured tuple `(False, None, INVALID_TARGET)` and assert zero policy/handler calls separately for each malformed input family. Ensure authorization decisions never trigger DNS, HTTP, scanning, evidence
   writes, or executor calls for invalid authorities.
4. Preserve valid explicitly authorized and unlisted-host behavior;
   distinguish synthetic fixture authorization from trusted consent.
5. Do not swallow exceptions from downstream authorization policies as malformed URL errors; policy infrastructure failures must remain distinguishable while handlers stay uncalled. A handler failure after a legitimate reference delegation must also propagate rather than be silently converted into an INVALID_TARGET denial. Malformed input must not inspect authorization or labels. A closing IPv6 authority bracket must be followed only by an optional port separator and valid port, never arbitrary trailing text. Brackets appearing only in path, query, or fragment components must not be treated as authority delimiters; use the parsed netloc rather than splitting the raw URL on `/`.\n6. Convert each `expectedFailure` in
   `tests/test_scope_malformed_ipv6_bracket_contract_20261009.py` to ordinary
   passing tests after the production fix. An XFAIL result is **not** a green
   security acceptance signal.
7. Demand hosted and canonical VPS CI on the **exact** merge candidate commit,
   plus source-owner review and trusted pre-I/O grant enforcement.

## Release state
**DRAFT / HOLD.** Do not merge or deploy on the strength of these offline
fixtures. Related live-grant provenance, revocation, and pre-dispatch
authorisation work remains independently gated by #107/#1128.
