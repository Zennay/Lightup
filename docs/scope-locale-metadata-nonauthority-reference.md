# Scope authorization: locale and display timezone are non-authoritative

## Integration contract (reference only)

Language preference, locale, localization headers, browser timezone, display timezone,
formatted timestamps, and human-readable translated approval labels are untrusted
presentation metadata. They MUST NOT determine whether an active assessment can start,
extend the time window of a grant, select a tenant/request, change a capability, or
convert a revoked/inactive grant into a live one.

Authorization checks require a current issuer-owned authenticated grant, exact
tenant/request/capability/revision binding, strict typed active state, independently
trusted UTC time, revocation checks and per-dispatch revalidation. Human-facing local
times may be rendered only **after** an authoritative UTC decision and must never be
round-tripped as authorization state. DST gaps, duplicate hours, locale-specific case
folding and translated display labels are not allowed to broaden permission.

## Offline evidence

Run `python -m unittest discover -s tests -p 'test_scope_locale_metadata_nonauthority_reference.py' -v`.

The synthetic suite asserts that changing locale/timezone metadata never changes
an otherwise equal consistency verdict, and never rescues an inactive grant,
wrong tenant, wrong request, revision or capability. Type-confused active fields,
revisions and forged dataclass subclasses are rejected.

## Boundaries and release gate

This is an isolated, stdlib-only **reference model**, not an integrated production
gate, real issuer authentication, signature check, trusted-clock implementation,
permission, or test-run activation. It deliberately neither consults a clock nor
accepts a human-formatted timestamp as authorization authority.
Only this document and its new test module are modified. No DNS, sockets,
network, real targets, credentials, scanners or dispatch.

Production executor integration remains with the existing scope source owner
(PR #107). Keep this change in draft until independent owner review, exact-head
hosted Python 3.11/3.14 and canonical permanent VPS evidence. Any positive
synthetic test is a necessary consistency condition only; real-target activation
remains disabled.
