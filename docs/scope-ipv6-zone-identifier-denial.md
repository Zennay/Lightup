# IPv6 zone-identifier authority isolation (offline RED acceptance)

## Issue
RFC 4007 scoped IPv6 literals carry a zone identifier (for example `fe80::1%eth0`).
The zone is local interface context, not a portable authorized asset identity.
Python's `ip_address` accepts zone-suffixed IPv6 literals, so a generic
`is_link_local` or loopback membership shortcut must not silently admit them.

## Required decision contract
- Before evaluating loopback/private-lab or explicit-network shortcuts, reject
  any IPv6 literal with a zone identifier as `INVALID_TARGET`.
- Apply the same rule to URL-escaped `%25` zone forms; neither URI parsing nor
  normalization may silently strip the zone and mint authority.
- An unscoped `[::1]` remains a canonical loopback control.
- No DNS resolution, network traffic, target interaction, capability dispatch,
  remediation, or broadening of authorizations is permitted.

## Collision boundary
This is tests/docs-only RED acceptance; `src/lightup/scope.py` and
`src/lightup/models.py` belong to active production owners.
Do not merge until owning source code makes regressions green and current-head
self-hosted CI has passed.

## Offline command
`PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_ipv6_zone_identifier_denial.py' -v`
