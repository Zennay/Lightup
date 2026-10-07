# Scope authorization arbitrary auth-scheme redaction

## Boundary

Complete HTTP authorization header lines may use authentication schemes beyond
Basic and Bearer. Credential payloads for those schemes can still be reusable or
security-sensitive and therefore must not survive the central text-redaction
boundary.

For a complete `Authorization:` or `Proxy-Authorization:` header line,
LightUp keeps the header name and syntactically bounded auth-scheme token, then
replaces the remaining payload with `[REDACTED]`.

Examples include Digest, Negotiate and signed authorization schemes. Existing
inline Basic/Bearer redaction remains in place for diagnostic fragments that are
not represented as standalone header lines.

## Safety properties

This is text sanitization only. It does not authenticate a caller, parse or
verify the credential, modify a grant, expand scope, alter activation, invoke a
target, or change remediation/retest authority.

The slice is stacked after the narrower credential-redaction contracts so each
boundary remains independently reviewable and exact-head testable.
