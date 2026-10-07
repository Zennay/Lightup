# Scope authorization cookie-session redaction

## Boundary

HTTP cookie headers can carry authenticated-session material that is reusable
independently of the authorization record that originally permitted a request.
Those values must not survive LightUp's central text-redaction boundary.

The redactor therefore replaces the full value of header lines named:

- `Cookie:`
- `Set-Cookie:`

Matching is case-insensitive and limited to a single header line. The header
name and surrounding non-cookie lines remain visible for diagnostics, while
cookie values and `Set-Cookie` attributes are removed together.

## Safety properties

This change only removes session material from text. It does not interpret
cookie values, create sessions, modify grants, widen scope, alter activation,
enable target interaction, or change remediation/retest authority.

This contract is stacked after the authorization-header and URL-userinfo
credential-redaction slices so each defensive boundary remains independently
reviewable and testable.
