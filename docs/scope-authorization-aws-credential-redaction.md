# Scope authorization AWS credential redaction

## Boundary

AWS credentials can appear under configuration keys even when the value does
not match the older `AKIA...` access-key identifier shape. Temporary
credentials also use different access-key prefixes and session tokens.

The central redactor therefore treats these keys as credentials in plain
assignments and quoted JSON/JSON-like diagnostics:

- `aws_secret_access_key`;
- `aws_access_key_id`;
- `aws_session_token`.

Underscore and hyphen separator variants are covered. Key names and unrelated
query/JSON context remain visible while credential values are replaced with
`[REDACTED]`. Non-credential AWS configuration such as `aws_region` remains
unchanged.

## Safety properties

This is defensive text sanitization only. It does not call AWS, validate a
credential, authenticate a principal, modify a grant, widen target scope, alter
activation, invoke a target, or change remediation/retest authority.

Literal AWS access-key-ID redaction remains in place as an independent
credential-shape backstop.
