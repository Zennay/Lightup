# Malformed IPv6 authority — source-owner acceptance gate (2026-10-09)

Owner: scope/authorization production integration (#107, #1128).
Regression PR: #1131 (draft). These are **synthetic offline** URLs, never customer-authorized targets.

## Gap
`ScopePolicy.normalize_host` calls `urllib.parse.urlparse` without catching
`ValueError`. The Python parser raises on unbalanced `[` or `]` in URL
authorities. `ScopePolicy.decide` therefore can raise rather than return a
structured denial. This is not approval to execute target work.

## Required contract
1. Catch invalid authority/parser failures at the normalization boundary.
2. Deny malformed URLs with `allowed=False`, `reason=INVALID_TARGET`, and
   `normalized_host=None`.
3. Ensure authorization decisions never trigger DNS, HTTP, scanning, evidence
   writes, or executor calls for invalid authorities.
4. Preserve valid explicitly authorized and unlisted-host behavior;
   distinguish synthetic fixture authorization from trusted consent.
5. Convert each `expectedFailure` in
   `tests/test_scope_malformed_ipv6_bracket_contract_20261009.py` to ordinary
   passing tests after the production fix. An XFAIL result is **not** a green
   security acceptance signal.
6. Demand hosted and canonical VPS CI on the **exact** merge candidate commit,
   plus source-owner review and trusted pre-I/O grant enforcement.

## Release state
**DRAFT / HOLD.** Do not merge or deploy on the strength of these offline
fixtures. Related live-grant provenance, revocation, and pre-dispatch
authorisation work remains independently gated by #107/#1128.
