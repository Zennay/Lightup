# Scope authorization URL-userinfo redaction

## Boundary

Target and evidence text may retain a URL for reproducibility, but credentials
embedded in HTTP(S) URL userinfo are not part of authorization authority and
must not survive the central redaction boundary.

Examples:

- `https://alice:secret@example.test/path` becomes
  `https://[REDACTED]@example.test/path`.
- `http://opaque-token@example.test/resource` becomes
  `http://[REDACTED]@example.test/resource`.
- A URL without userinfo remains unchanged.

The scheme and target context after `@` remain visible so evidence can still
identify the scoped host, port, path, query and fragment without exposing the
credential material.

## Safety properties

This is a text-sanitization change only. It does not reinterpret URLs, add
targets to scope, create grants, modify activation, enable a capability, invoke
network access, or alter remediation/retest authority.

This contract is stacked after the Basic/Bearer authorization-header redaction
slice so both credential boundaries remain independently reviewable.
