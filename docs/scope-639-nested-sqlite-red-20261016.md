# #639 — installed SQLite mixed-entry corruption acceptance (2026-10-16)

**Project posture:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.
**Original source owner:** draft PR #554 at immutable `4c8d5651fc0e23f94514daae56b4e5fe0549de37`.
**Independent parent:** existing #639 acceptance-only branch at immutable `d4908a306abf4258908049767b63782bad1f8740`.
**This change:** one newly named test module and this new contract only. No owner files, app code, grant issuance logic, web ingress, workflow or shared runner changed.

## Specific deficiency exposed

The installed `DomainStore.resolve_authorization_for_execution()` on the frozen #554 owner source checks whether each persisted scope JSON *container* is an array but does not confirm the exact Python type of **every array element** before reconstructing scope. That can leave an in-memory current `AuthorizationGrant` with null/boolean asset and exclusion entries, or raise `TypeError` from capability registry lookup when a nested object was persisted. These are local fabricated database-corruption witnesses, **not evidence of real customer data compromise or target activity**.

## Eight runnable methods

- Canonical current grant with one fictional hostname and a known passive capability resolves unchanged.
- Three ordinary PASS controls: outer null, JSON object and scalar capability container are denied and untouched in SQLite.
- Three **deliberately expected source REDs**: mixed allowlist + null, mixed exclusion + false, mixed capabilities + object must deny without throwing or rewriting.
- One **ordinary independent replay oracle** demands exact observed legacy outcomes (`granted`, `granted`, `raised:TypeError`), preventing an arbitrary crash, test skip or altered source from being misreported as the intended source RED. A production repair must convert the 3 expectedFailures to genuine PASS and deliberately retire/update the legacy oracle.

All rows live in a fresh temporary SQLite file. The test snapshots all three original raw JSON columns before/after decisions; it does not grant permissions, access a network, scan assets or invoke tools. It checks only in-process decision preparation. The fixture `app.example.invalid` is deliberately fictitious.

## Owner handoff and release gates

The source owner #554 / broader durable grant #107 must reject malformed nested entries **before returning any executable grant**, with an exact-type, nonblank and explicit-capability contract; malformed records must remain unchanged and cannot propagate unexpected exceptions. After review, run both previous #639 and this new suite against the **owner-repaired exact source head**, verify genuine GREEN instead of expected RED, then verify original hosted Python 3.11/3.14 and permanent registered `vps-bb300bba` runner with complete immutable-head logs.

This add-only test does **not** prove complete ingress protection, valid client consent, revocation, registry binding or ready-to-release production. Independent privacy/security review and explicit human GO remain outstanding. **No merge, deploy, real grants, targets, scans, or release.**
