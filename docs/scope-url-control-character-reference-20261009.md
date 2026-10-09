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

## Unicode invisible-character policy specimen

The offline raw pre-parser now rejects all Unicode whitespace and Unicode general categories `Cc`, `Cf` and `Cs` anywhere in the raw target, including zero-width joiners, bidi overrides/isolates and BOM-like format characters. Three additional ordinary tests cover 18 format-character/position combinations, five internal-whitespace cases and unchanged percent-encoded Unicode control sequences. Percent-encoded strings are not authorized by this check: decoded target semantics must be validated independently before real I/O. The reference is still not production enforcement.

## Unicode call-isolation and normalization controls

Two more ordinary offline tests prove that Unicode format controls and lone surrogate input never invoke the downstream scope-policy decision, while canonically composed and decomposed accent sequences are delegated **unchanged**. The reference now has 15 ordinary tests. These checks do not imply Unicode hostname acceptance or consent: downstream canonical host matching, DNS rebinding checks, grant verification and zero actual network-handler invocations remain separate owner gates.

## Hostile polymorphic target objects

Two more ordinary reference tests assert strict built-in `str` typing: a hostile `str` subclass with throwing iteration/indexing/stringification hooks and a non-string object with throwing `__str__`, `__bool__` and `__iter__` methods both fail closed without invoking downstream policy evaluation. The specimen intentionally never coerces hostile input. This is strictly offline pre-policy reference behavior, not production authorization enforcement.

## Malformed target isolation from grant and labels

Two additional ordinary offline tests use poison authorization and labels objects to assert that an invalid raw target is rejected before either metadata object is inspected, and before any policy call. These are pre-parser evaluation-order contracts only; trusted production grant verification is still required for valid targets. Total 19 ordinary reference methods, plus 16 legacy methods including 12 unresolved RED/XFAIL contracts.

## Unicode non-control boundary controls

Two ordinary offline tests preserve non-control Unicode letters, marks and symbols for downstream canonical validation without treating them as authorized, and reject lone high/low UTF-16 surrogates before any scope policy invocation. Total: 21 ordinary reference cases, alongside 16 legacy cases including 12 unresolved RED/XFAIL requirements. No production grant or dispatch behavior changes.
