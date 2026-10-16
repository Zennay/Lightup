# Issue #639: executable pure review of nested durable scope entries

## Purpose and explicit NON-authority

This work remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**.
The new opt-in reference `tests/scope_639_strict_entry_reference.py` is **not**
imported by LightUp production modules. It does not issue `AuthorizationGrant`
objects, make policy decisions, acquire permissions, issue tenant authority, talk
to hosts or scan anything. Even a successful shape review alone MUST NEVER
permit active execution.

This file is intended solely as reviewable, independently testable behavior
for the resolver source owner [#554](https://github.com/Zennay/Lightup/pull/554).
It is not a safe hotfix by itself.

## Contract

`review_scope_entries(assets_json=..., excluded_assets_json=..., allowed_capabilities_json=...)`

- Requires **exact built-in strings** as all three raw SQLite JSON columns.
  A subclass with hostile `__eq__`, `strip`, `__str__` cannot be used
  for callback-driven type confusion before it is rejected.
- Each JSON value must decode to an exact **array**. Arbitrary scalar, object,
  invalid JSON and excessive nesting deny as `None`, not a repaired row.
- **Every nested item** is an exact built-in nonblank string. No filtering,
  JSON-to-string conversion, case normalization, trimming or dropping invalid
  elements. Invalid *one* element rejects the entire scope.
- Assets and allowed-capability arrays must each be **nonempty**; the exclusion
  array can be empty. This matches issue #639 required invariants.
- A valid result is a `ReviewedScopeEntries` **immutable named tuple**, never
  a grant, permission or risk decision. It deliberately performs **no**
  cap-registry lookup, revocation, clock or client validation.
- Rejects without any SQLite write. Historical raw rows remain available
  for audit, and the caller cannot use acceptance to bypass any other gate.

## Concrete tests

`tests/test_scope_639_strict_entry_reference.py` runs isolated stdlib
`unittest` assertions for canonical value preservation, optional exclusions,
immutable outputs, malformed containers, nested JSON `null/bool/number/object`,
blank Unicode whitespace, hostile subclasses/objects, raw SQLite types,
**900 deterministic seeded mixed-entry corruption subcases** across every
persisted array,
deep nesting, an explicit **no filesystem/socket/SQLite/subprocess I/O**
canary for the pure reviewer, and one separate real temporary SQLite mutation
+ nonwrite proof.
No target socket, command execution, credentials or real grants.

Run through the hosted offline preflight Python 3.11/3.14 and original
producer integration jobs at the exact immutable HEAD; record both positive
results and any failures rather than only relying on check badges.
The independent, still-open installed-source RED tests remain in
`tests/test_scope_639_nested_sqlite_red_20261016.py`. The reference test
being green DOES NOT repair those REDs.

## Deployment and conflict ownership

Original source owner #554 owns the actual
`DomainStore.resolve_authorization_for_execution` change. To integrate
safely, apply equivalent exact nested-array checks **inside** that already
owned resolver before `_grant_from_row`, then run old + new tests as
ordinary true PASS, remove obsolete source-behavior replay expectations, and
verify all tenant/provenance/registry/risk/revocation/time and zero-target-I/O
properties. Other pending branches and source files must not be copied,
rebased or force pushed without ownership review.

Hosted green alone cannot substitute for permanent VPS labels/host proof
([operator #1144](https://github.com/Zennay/Lightup/issues/1144)),
independent security/privacy approval, verifiable original
client/operator consent, live revocation and explicit human GO.
**No merge / deploy / live grants / actual targets / scans / handlers.**
