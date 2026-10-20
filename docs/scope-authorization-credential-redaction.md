# Scope authorization credential redaction

## Boundary

Authorization decisions and authorization evidence are separate concerns. Audit
metadata such as a grant reference may remain visible where the product contract
requires provenance, but reusable HTTP credentials must not survive the central
text-redaction boundary.

The redactor therefore treats credential material following these schemes as
sensitive:

- `Authorization: Bearer <credential>`
- `Authorization: Basic <credential>`
- `Proxy-Authorization: Bearer <credential>`
- `Proxy-Authorization: Basic <credential>`

Matching is case-insensitive. The header name and authentication scheme remain
visible for diagnostics; only the credential value is replaced with
`[REDACTED]`.

## Safety properties

This change only removes credential material from text. It does not create or
validate grants, widen target scope, alter activation mode, change risk
authority, enable network access, or execute any target-capable operation.

Regression coverage must continue to prove existing Bearer and generic secret
redaction while protecting valid Basic credentials, including padded base64.
