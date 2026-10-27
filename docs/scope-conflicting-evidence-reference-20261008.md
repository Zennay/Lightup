# Conflicting authorization evidence — offline acceptance reference

This document defines an **illustrative offline-only** deny-by-default acceptance matrix. It is **not** a production authorization implementation, permission grant, trusted audit receipt, or execution safety proof.

## Contract for the production owner

At the moment of activation, join the requested action to one current, trusted and independently verified approval receipt. The receipt must bind the same exact request ID, tenant, canonical asset, capability and approval revision. Missing or contradictory fields must deny; matching four of five fields is not sufficient. Historical approval cannot override current revocation. Both approval and revocation flags must be actual booleans, not truthy/falsy values.

The production owner must independently establish issuer identity, review separation, persisted provenance, expiry/time window, freshness, tenant isolation, canonical target identity and atomic revocation checks. None of those are established by this small synthetic reference.

## Synthetic coverage

The corresponding test suite checks a consistent reference case; every missing required field; independent mismatch of request, tenant, asset, capability or revision; multiple mismatches; revocation precedence; type-confused flags and identifiers; and malformed envelope inputs.

## Reproduction

`python -m unittest discover -s tests -p 'test_scope_conflicting_evidence_reference_20261008.py' -v`

## Collision / safety boundary

New files only: this document and `tests/test_scope_conflicting_evidence_reference_20261008.py`. No changes to production scope, activation, revocation, audit, execution, web, target workers or existing tests. No network calls, target interaction, scanning, activation or permission widening. Keep this change draft pending exact-head CI/VPS verification and integration-owner review.
