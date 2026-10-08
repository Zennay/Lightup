# Authorization identifier lexical boundary — offline reference (2026-10-08)

## Purpose
Protect tenant, grant, run and reviewer identifier lookups from type confusion and silent canonicalization. This is a **proposed acceptance constraint**; the owning production contract must decide whether the same canonical ASCII format applies to each identifier field. Existing stored identifiers require migration/compatibility review before adoption.

## Fail-closed reference rule
Only an **exact** Python `str` containing 1–64 ASCII lowercase letters, digits, underscore or hyphen is accepted. First and last characters must be lowercase ASCII alphanumeric. Do not trim, case-fold, normalize Unicode, stringify objects, or accept subclasses. Reject slash, backslash, control, whitespace, Unicode confusables and overlength input. Apply the same rule at ingest, persistence boundary, comparison and authorization lookup; never repair invalid identifiers into potentially authorized principals.

## Safety and integration
The accompanying isolated unittest module tests a pure offline reference predicate, **not** the production API or grant/executor. No production permission, active scan or target dispatch is enabled. Integration requires the #107 executor / approval owner to confirm field-by-field identifier grammar, collision policy, existing-data handling and trusted issuer binding. This contract does not replace tenant authorization, approval provenance, revocation or atomic leases.

## Reproduce
`python -m unittest discover -s tests -p 'test_scope_identifier_boundary_reference_20261008.py' -v`

Keep the PR draft until exact-head hosted CI, permanent VPS test proof and production-owner review. Tests do not constitute authorization proof.
