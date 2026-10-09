# Scope URL control-character normalization — offline security reference

**Owner boundary:** isolated scope-authorization test lane, 2026-10-09. No production edits or updates to other workers' branches.

## Defect characterization

Python's `urllib.parse` preprocessing removes ASCII TAB (U+0009), LF
(U+000A) and CR (U+000D) from a URL before hostname extraction. In the
current `ScopePolicy.normalize_host`, this permits an attacker-supplied
hostname with embedded controls to be silently normalized into an explicitly
allowlisted host. These inputs should be rejected, not repaired.

`tests/test_scope_url_control_characters_20261009.py` contains sixteen
offline unittest cases: three positive/negative controls, twelve deliberately
RED `expectedFailure` denial requirements, and one table-driven unknown
host control. Seven additional RED cases cover raw CR without scheme, TAB in
path, LF/CR in query, DEL in path and leading ASCII space/LF. The RED cases are **not** passing safety guarantees.

## Required owner repair

1. Reject raw target values containing ASCII control characters (at least
   U+0000–U+001F and U+007F) and leading whitespace before normalization **before** `urlparse` or normalization.
2. Return `INVALID_TARGET` rather than accepting a sanitized public hostname.
3. Verify pre-I/O production grant provenance, client/engagement/asset/capability
   binding and revocation independently; synthetic `Authorization` above is
   not authenticated customer consent.
4. Convert the twelve expected failures into ordinary **passing** fail-closed
   assertions after owner implementation; cover handler invocation count = 0.
5. Obtain exact-head hosted and canonical permanent VPS tests, source-owner
   review and approval before any merge or activation.

Run offline: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_url_control_characters_20261009.py' -v`.

**HOLD**: No live targets, DNS, scanning, permission issuance, production
executor edits, deployment, or automatic merge are authorized by this reference.

## Concrete fail-closed offline reference

`tests/test_scope_raw_target_preparser_reference_20261009.py` now contains six additional, **ordinary (non-XFAIL)** offline unit methods with a pure `validate_raw_target` / `reference_decide` specimen. Its table-driven test checks all 33 ASCII control/DEL codepoints across leading, authority, path and query positions (132 denial combinations), plus leading Unicode whitespace, invalid types, and controls for clean allowlisted, unauthorized and unlisted inputs. The reference is intentionally not wired into production; owner of #107 must adopt equivalent raw-input rejection in the trusted pre-I/O path before any real assessment. A passing reference suite does not close the twelve legacy RED cases or prove a verified grant.

## Pre-policy invocation gate

The offline reference now contains eight ordinary tests, including mock-backed checks proving malformed raw targets call the downstream scope-policy decision function **zero times**, whereas a valid raw target delegates exactly once with the original `Target` object. This is a reference-layer no-call assertion only: it does **not** establish that the production ToolExecutor or network handler is blocked. The integration owner must add equivalent pre-I/O zero-handler-call tests on the trusted executor before release.

## Raw-vs-encoded input fidelity

The offline reference now includes ten normal tests. New mock-backed assertions preserve the original immutable `Target` (including labels and authorization reference) and distinguish literal raw ASCII controls from percent-encoded byte sequences (`%0A`, `%0d`, `%09`, `%7F`). The pre-parser specimen delegates percent-encoded values unchanged; it **does not approve** them for dispatch. Production must separately validate canonicalized authority/path semantics, redirect reauthorization and verified permission before all target I/O. This prevents double-decoding or accidental implicit grant issuance from being treated as a permitted scope transition.
