# Scope URL control-character normalization — offline security reference

**Owner boundary:** isolated scope-authorization test lane, 2026-10-09. No production edits or updates to other workers' branches.

## Defect characterization

Python's `urllib.parse` preprocessing removes ASCII TAB (U+0009), LF
(U+000A) and CR (U+000D) from a URL before hostname extraction. In the
current `ScopePolicy.normalize_host`, this permits an attacker-supplied
hostname with embedded controls to be silently normalized into an explicitly
allowlisted host. These inputs should be rejected, not repaired.

`tests/test_scope_url_control_characters_20261009.py` contains thirteen
offline unittest cases: three positive/negative controls, nine deliberately
RED `expectedFailure` denial requirements, and one table-driven unknown
host control. Four additional RED cases cover raw CR without scheme, TAB in
path, LF in query, and DEL in path. The RED cases are **not** passing safety guarantees.

## Required owner repair

1. Reject raw target values containing ASCII control characters (at least
   U+0000–U+001F and U+007F) **before** `urlparse` or normalization.
2. Return `INVALID_TARGET` rather than accepting a sanitized public hostname.
3. Verify pre-I/O production grant provenance, client/engagement/asset/capability
   binding and revocation independently; synthetic `Authorization` above is
   not authenticated customer consent.
4. Convert the nine expected failures into ordinary **passing** fail-closed
   assertions after owner implementation; cover handler invocation count = 0.
5. Obtain exact-head hosted and canonical permanent VPS tests, source-owner
   review and approval before any merge or activation.

Run offline: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_url_control_characters_20261009.py' -v`.

**HOLD**: No live targets, DNS, scanning, permission issuance, production
executor edits, deployment, or automatic merge are authorized by this reference.
