# Scope authorization: percent-encoding ambiguity acceptance reference

Status: **proposal only / M7-ST5 / offline / fail-closed**.

## Threat boundary
A request may supply a scope resource identifier whose serialized form differs
from an identifier obtained after one or more URL-decoding passes. Components
that compare the predecoded and decoded strings can disagree about the
authorized resource, especially for encoded separators, dot segments, and
double-encoded percent escapes.

## Proposed acceptance policy
- Require an explicitly defined canonical grammar for every scope identifier
  at the **same boundary** used for approval and at dispatch time.
- The accompanying unit tests model a restrictive **single segment** ASCII
  grammar; never assume this is compatible with URL paths, whole target URLs,
  hostnames, or the production policy without source-owner approval.
- Deny encoded aliases, malformed percent escapes, delimiter characters,
  Unicode confusables, and non-exact Python strings. Do not repeatedly decode
  untrusted scope strings into authority.
- Carry a trusted, typed, issuer-bound canonical identifier across queued and
  running operations; recheck the live grant before each privileged step.
- Record a bounded denial reason without logging raw credentials or tokens.

## Integration decision required
Production policy/executor owner **PR #107** should decide the grammar per
identifier type and where canonicalization is enforced, then add integration
tests with real policy entry points. The isolated helper in
`tests/test_scope_percent_encoding_boundary_reference_20261008.py` is
**not** imported by production, grants no permission, and proves no protection
in the running executor.

## Verification
```sh
python -m unittest discover -s tests -p 'test_scope_percent_encoding_boundary_reference_20261008.py' -v
```
Exact-head hosted CI, canonical permanent VPS evidence, independent review,
and source-owner integration are still required before promotion. No targets,
DNS, sockets, scans, or capability handlers are contacted by these tests.
