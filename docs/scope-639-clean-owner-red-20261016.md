# #639 clean owner-source real-SQLite corruption acceptance (2026-10-16)

**Project: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**

## Immutable base / ownership
This independent child starts **directly** from unchanged original source-owner [PR #554](https://github.com/Zennay/Lightup/pull/554) at `4c8d5651fc0e23f94514daae56b4e5fe0549de37`. It intentionally **does not inherit** the older, intentionally RED source-acceptance `tests/test_scope_authorization_persisted_scope_entry_integrity.py` from issue #639's older draft branch. See [#1473](https://github.com/Zennay/Lightup/pull/1473) for original six FAIL reproduction. Neither original source owner nor competing branch is modified. Only two brand-new own test/docs paths on this child.

## Eighteen executable unit methods (local fictional SQLite only)
- **Eleven ordinary positive/denial controls:** unmodified canonical grant resolves, invalid outer null/object/scalar JSON denied, malformed JSON array denied, raw SQLite binary and numeric scope field denied, empty exclusion list accepted, plus strict exact-original-source RED replay.
- **Seven deliberate OPEN original-source REDs:** empty allowlist, blank mixed allowlist, null mixed allowlist, boolean mixed excluded asset, unhashable mixed capability map, and explicit mixed numeric asset/boolean exclusion denied before downstream use. Each test requires deny-without-exception and no durable row rewrite, but source #554 currently fails the requirement.
- The *ordinary replay* oracle makes exact installed old outcomes explicit (in-memory grant, or `raised:TypeError`), so a random exception, altered setup or test skip cannot masquerade as the intended known source RED.

A raw before/after snapshot of the three serialized scope columns is retained for every malformed input. The fixture uses invented `example.invalid` identifiers, ephemeral SQLite, no clients or network access, and no handler/target/scan execution. An open source RED is neither a repaired vulnerability nor release authorization.

## Why this independent lane matters
The previous child [#1473](https://github.com/Zennay/Lightup/pull/1473) inherited six independently FAILing tests and its overall [hosted workflow #38850028844](https://github.com/Zennay/Lightup/actions/runs/38850028844) was red on both Python versions, despite all eight new tests behaving as designed. This child isolates the actual unchanged source owner's test baseline so both Python unit and real producer integration can be measured without obscuring genuine open REDs. **Any green CI with expectedFailures remains test-protocol evidence, not secure runtime permission.**


## W2 downstream in-memory consequence (independent, still no target I/O)
Added **four new tests** in the same worker-owned test file: two further intentional OPEN RED requirements that numeric asset / boolean exclusion entries cannot leave durable resolver, plus **two ordinary green reproduction witnesses** against original source. With temporary fictional SQLite corruption, source #554 presently returns a non-executable-only *in principle* in-memory grant containing `123` or `False`. A local `ScopeDefinition.allows_asset("app.example.invalid")` call then raises `AttributeError` at `.strip()`. Each witness checks the exact tuple, matching exception class/message and unchanged SQLite bytes, preventing an unrelated throw from standing in for the problem. **No handler, network socket, real target, scan or asset interaction occurs.** This is a local in-process failure boundary, not an observed external effect.

## Owner repair contract
Original resolver owner #554 / durable execution authority #107 should require exact built-in nonblank strings for **each** JSON array entry, non-empty assets and capabilities (but empty exclusions permissible), and deny bad persisted rows **before** constructing/exposing an executable grant or calling registry lookups. Preserve raw forensic rows, tenant/engagement, revocation, capability/risk, scope and clock checks. After source repair, convert the seven open expectedFailures to ordinary PASS and intentionally retire the old-behavior replay oracle. Independently verify hosted Python 3.11/3.14 and registered permanent VPS `vps-bb300bba` with exact immutable-head proof.

**No source owner changes, workflow/runners, merges, live grant issuance, customer consent, external target actions, scans, deployment, or release by this test-only child.** Security/privacy review, genuine client+operator authorization and explicit human GO remain required.
