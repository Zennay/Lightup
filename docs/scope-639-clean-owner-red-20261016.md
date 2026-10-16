# #639 clean owner-source real-SQLite corruption acceptance (2026-10-16)

**Project: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**

## Immutable base / ownership
This independent child starts **directly** from unchanged original source-owner [PR #554](https://github.com/Zennay/Lightup/pull/554) at `4c8d5651fc0e23f94514daae56b4e5fe0549de37`. It intentionally **does not inherit** the older, intentionally RED source-acceptance `tests/test_scope_authorization_persisted_scope_entry_integrity.py` from issue #639's older draft branch. See [#1473](https://github.com/Zennay/Lightup/pull/1473) for original six FAIL reproduction. Neither original source owner nor competing branch is modified. At the latest W8 head this child has exactly SIX entirely new owned paths (one pure **unwired** source reviewer, three tests/reference paths, and two docs); no existing owner/worker/CI/runner file modified.

## Twenty-three executable SQLite source-acceptance unit methods (local fictional SQLite only)
- **Fourteen ordinary controls and exact source-behavior witnesses:** canonical grant, outer JSON null/object/scalar and malformed syntax denial, SQLite nontext/numeric refusal, empty excluded list, deterministic old-resolver behavior replay, downstream in-memory matcher crash reproductions, same-raw-row pure-reviewer versus existing resolver comparison, immutable canonical text scope shape, and a **temporary in-test-only** same-row resolver seam proving fail-closed denial without touching production code.
- **Nine deliberately OPEN original-source REDs:** empty assets, whitespace-only and null mixed asset, numeric asset, nested object asset, blank and boolean excluded-asset entries, and unhashable capability map (plus a second boolean-exclusion denial witness). Each test requires deny-without-exception and no durable row rewrite, but source #554 currently fails the requirement.
- The *ordinary replay* oracle makes exact installed old outcomes explicit (in-memory grant, or `raised:TypeError`), so a random exception, altered setup or test skip cannot masquerade as the intended known source RED.

A raw before/after snapshot of the three serialized scope columns is retained for every malformed input; the test-only seam resets **all three** columns between corrupt cases, including before the final original resolver replay. Its earlier missing reset caused one unexpected `TypeError` in hosted [W8 trial #38853869375](https://github.com/Zennay/Lightup/actions/runs/38853869375); fixed in subsequent commit, with successful revalidation on immutable SHA `89fd681f2bf1ca3531d1bacc2221a7caf297312a` via [hosted #38853977621](https://github.com/Zennay/Lightup/actions/runs/38853977621): **4/4 jobs, 611 units OK with nine still-OPEN source expectedFailures, plus 86 genuine producer integrations OK on both Python 3.11 and 3.14**. The fixture uses invented `example.invalid` identifiers, ephemeral SQLite, no clients or network access, and no handler/target/scan execution. An open source RED is neither a repaired vulnerability nor release authorization.

## Why this independent lane matters
The previous child [#1473](https://github.com/Zennay/Lightup/pull/1473) inherited six independently FAILing tests and its overall [hosted workflow #38850028844](https://github.com/Zennay/Lightup/actions/runs/38850028844) was red on both Python versions, despite all eight new tests behaving as designed. This child isolates the actual unchanged source owner's test baseline so both Python unit and real producer integration can be measured without obscuring genuine open REDs. **Any green CI with expectedFailures remains test-protocol evidence, not secure runtime permission.**


## W2 downstream in-memory consequence (independent, still no target I/O)
Added **four new tests** in the same worker-owned test file: two further intentional OPEN RED requirements that numeric asset / boolean exclusion entries cannot leave durable resolver, plus **two ordinary green reproduction witnesses** against original source. With temporary fictional SQLite corruption, source #554 presently returns a non-executable-only *in principle* in-memory grant containing `123` or `False`. A local `ScopeDefinition.allows_asset("app.example.invalid")` call then raises `AttributeError` at `.strip()`. Each witness checks the exact tuple, matching exception class/message and unchanged SQLite bytes, preventing an unrelated throw from standing in for the problem. **No handler, network socket, real target, scan or asset interaction occurs.** This is a local in-process failure boundary, not an observed external effect.

## Test-only source versus pure-guard evidence (W8)

The additional source-versus-guard method reads the SAME real temporary
SQLite scope field snapshot and proves that the unmodified source sometimes
returns an in-memory execution grant or raises `TypeError` while the strictly
bounded pure helper returns `None`. Another new method patches ONLY the
synthetic test instance's `_grant_from_row` seam, checking the exact already
fetched joined SQLite row before reconstruction; seven corrupt variants are
then denied by the existing caught `ValueError`, while canonical authorization
still reconstructs. After test-only patch removal, the original owner-source
leak is deliberately reproduced. This is a review **feasibility proof**, not
a runtime repair, issuer consent or release authority. The helper is not
installed in the production resolver. The owner must implement the real
pre-reconstruction guard on the existing joined row and preserve provenance,
risk, live revocation, temporal, tenant, capability and consent checks.

## Owner repair contract
Original resolver owner #554 / durable execution authority #107 should require exact built-in nonblank strings for **each** JSON array entry, non-empty assets and capabilities (but empty exclusions permissible), and deny bad persisted rows **before** constructing/exposing an executable grant or calling registry lookups. Preserve raw forensic rows, tenant/engagement, revocation, capability/risk, scope and clock checks. After source repair, convert the nine open expectedFailures to ordinary PASS and intentionally retire the old-behavior replay oracle. Independently verify hosted Python 3.11/3.14 and registered permanent VPS `vps-bb300bba` with exact immutable-head proof.

**No source owner changes, workflow/runners, merges, live grant issuance, customer consent, external target actions, scans, deployment, or release by this test-only child.** Security/privacy review, genuine client+operator authorization and explicit human GO remain required.
