# LightUp · unified PRIVATE scope operator workroom

**Status: INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. Not approved for live use.**

This branch composes eight **existing independently owned** scope-authorization companion workrooms into one portable offline package, preserving their exact source bytes. It adds only a navigation hub, offline packaging, unsigned file inventory and operator instructions. It does **not** integrate or promote the original source-owner authorization engine, alter grants, verify client identity, dispatch work, contact a target, modify CI or produce security findings.

## Open and use

1. Open `scope-unified-workspace/index.html` in a local browser, or extract `scope-unified-workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip` first and open its same file. Do not open this bundle from a public web server, email previewer or shared cloud host.
2. Start at **Scope Intake Matrix** and create a HUMAN proposal. Its optional original Casebook import requires the genuine original owner's separately exported PRIVATE file. An arbitrary JSON file is not authenticated source/consent.
3. For an independently obtained original Casebook source history, open **Encrypted Casebook Transfer**, package the original files locally with a new password and convey the resulting packet by a separately trusted channel. Verify the recipient independently.
4. To compare *two human reviewer packages over precisely identical original source bytes*, use **Casebook Reconcile**. Source drift refuses the comparison; conflicts require deliberate HUMAN choices. Never equate a human status with a grant, revocation or finding verification.
5. **Casebook History** is an optional companion **CLI** and documentation, not a fourth ready-made HTML tool. Its original source-owner dependency is held in PR #1620. It is not activated, wired or patched by this bundle.

The start page makes **zero network requests**, uses **zero JavaScript**, contains its own exact-CSP-hash-pinned CSS, and does not write cookies, IndexedDB or localStorage. Each included standalone retains its original implementation, local privacy notices and operating limits. Imported source data and human notes can be confidential; encrypted files and passwords require independent recipient authentication.

## Source ownership and pinned input commits

| Original draft PR | Compartment (copied, byte-for-byte from pinned HEAD) | Exact pinned commit |
| --- | --- | --- |
| [#1676](https://github.com/Zennay/Lightup/pull/1676) | `scope-intake-matrix/` | `480e4c5e0ff6ffbf020719f0ab3c03c9d1162538` |
| [#1668](https://github.com/Zennay/Lightup/pull/1668) | `scope-casebook-history/` | `2e10197061fe7876dcd6458ae4fc70d9674af9d3` |
| [#1671](https://github.com/Zennay/Lightup/pull/1671) | `scope-casebook-transfer/` | `f40b0d2cf626e49bbd8f764968df132ba9d4365a` |
| [#1674](https://github.com/Zennay/Lightup/pull/1674) | `scope-casebook-reconcile/` | `7de3f5a5549c738eeb90f81c687c9a7d9c7cab3a` |

| [#1588](https://github.com/Zennay/Lightup/pull/1588) | `authorization-portfolio/` | `2ac15c5b24bf5646c3749c26fed577209b1b1221` |
| [#1577](https://github.com/Zennay/Lightup/pull/1577) | `withdrawal-desk/` | `0235d93fe285edc0cc49ea3aec3580b7dc4e1338` |
| [#1574](https://github.com/Zennay/Lightup/pull/1574) | `scope-vault/` | `49a569b2125a80dcaac21655febc07861afa0df2` |
| [#1567](https://github.com/Zennay/Lightup/pull/1567) | `studio/` | `71d9e5f760ef2bff46a72b979173bb3181179afb` |

This is a **snapshot**, not ongoing automatic propagation. Parent source-owner PRs and their branches stay untouched. Changes to those originals need a separately reviewed composition and a new frozen inventory. Duplicated or older assets must never be represented as current original authorization truth.

## Structural source routing without authenticating consent

The private handoff workroom includes its own **new source-inspector.js**, stitched into the existing CSP-pinned standalone. It rejects duplicate JSON keys, invalid UTF-8, oversized/unbounded JSON, and malformed declared original Studio DRAFT_ONLY, Casebook REVIEW_ONLY and operator-readiness REVIEW_ONLY source envelopes; unknown JSON remains **unverified/manual** and no arbitrary bytes become trusted. It shows category and non-sensitive source totals only, never injected inner HTML, original tenant IDs, client labels or asset hostnames. JSON imported through this companion still requires full independent re-validation by the *original receiving workroom*. This is not equivalent to source authentication or operator consent.

## Pin every imported original to its copied source bytes

The committed `PINNED-ORIGINALS.json` enumerates **all 60 copied original files** under eight owner compartments, with exact declared original PR HEAD, original relative path, byte size and SHA-256. `source_pins.py` is a fail-closed local **product build prerequisite**, not a QA suite: `build.py` refuses to package an added, removed, renamed, symlinked, size-changed or byte-changed original file, and rejects an unrecognized/mismatched source-head claim. To refresh originals deliberately, separately re-verify the exact upstream PR head, record all changed files and update the pin document in a dedicated reviewed composition commit. Never silently edit a copied original's code.

The committed SHA-256 inventory is **unsigned**: it detects accidental drift relative to this Git commit, but does not independently authenticate GitHub, the original developer, client/tenant identity, consent or release. Exact SHA content review, original source-owner approval and mandatory original hosted and named VPS CI still remain outside this offline bundle.

## Rebuild portable package (product build only)

Run on a trusted local/offline developer checkout:

```sh
python3 scope-unified-workspace/build.py
```

This deterministic Python-stdlib build generates `index.html`, `SOURCE-MANIFEST.json` and `LightUp-Scope-Offline-DRAFT-HOLD.zip`. The manifest lists file sizes, SHA-256 digests and original parent commits for **transport comparison only**. It is **unsigned**, not an independent proof of original authorship, authorized source, tenant identity, runtime behavior or security correctness. The ZIP has fixed metadata and is assembled atomically. It contains no data provided by an operator, browser session, account, customer or database.

## Additional operator-facing workflows

- **Five-screen Scope Studio** (`studio/index.html`, original held #1567): prepare offline `DRAFT_ONLY` scopes, effective CIDR/risk/change summaries, UTC schedule, human handoff. These documents are self-reports, never grants.
- **Withdrawal Coordination Desk** (`withdrawal-desk/standalone.html`, held #1577): import eligible ORIGINAL Studio draft bytes, write local urgent stop/withdrawal HUMAN contacts and source-bound follow-up. The desk does not contact a real source or STOP workers: separately notify the genuine authenticated grant owner and action-time revocation system.
- **Authorization Risk Portfolio** (`authorization-portfolio/standalone.html`, held #1588): accept separately obtained original operator readiness JSONs, triage HUMAN attention across multiple scopes, export source-minimal counts. This package does not include or impersonate the held source-owner operator CLI and cannot generate authentic original exports itself.
- **Private Scope Packet Vault** (`scope-vault/standalone.html`, held #1574): optionally bundle distinct self-authored scope/review files and names using its own local password protection. It cannot decrypt unrelated `.lupt`/`.lucb` originals, and does not authenticate an actual sender or recipient.

The original standalone products' file contracts remain independent; the hub is navigation, not an undisclosed auto-import or invisible bridge. A second app does not automatically see a first app's memory: HUMAN must choose and separately re-import the appropriate locally exported file.

## PRIVATE multi-workroom handoff shelf

Open `scope-unified-workspace/handoff.html` on a trusted offline browser. Import up to 16 local files (max 8 MiB/file, 32 MiB total), calculate SHA-256 in memory, choose a destination workroom and optionally download the unchanged original bytes. Known JSON route suggestions use bounded content-level format inspection with duplicate-key rejection, but are never producer, tenant or consent verification. Encrypted inputs stay opaque. The destination app receives no automatic transfer: the HUMAN operator must explicitly select the original file again in that app. No network, cookies or persistent browser storage.

Any collision of normalized (NFC/case-insensitive) original filenames now HOLDs the **whole** incoming batch, even when different bytes claim the same name; manually remove a prior version before introducing its replacement, so a case never silently switches between source revisions.

The workroom now has PRIVATE in-tab **local text search and HUMAN-stage filtering** for navigating the source-bound review desk; filters affect presentation only, never file admission, origin binding or the complete source inventory export.

Each selected original file now gets source-SHA-256-bound **local HUMAN triage**: unreviewed / preparing / escalated / documented-but-NOT-resolved, a team (security, privacy, client operations, platform or unassigned), and an optional 280-character PRIVATE note. These HUMAN values do not change the original source, signal real consent or revoke grants. Removing the original also removes its local HUMAN choices.

Two separately confirmed exports are available: an anonymous route-counts JSON without source identifiers; and a PRIVATE original filename+size+unsigned-digest+HUMAN stage/team/private note handoff containing potentially sensitive details, to be transferred only to authenticated recipients. Browser memory wiping is not guaranteed. No grants, dispatch or revocation are performed.

## Restore prior PRIVATE HUMAN review decisions against original files

Export **PRIVATE source inventory** after assigning HUMAN review stages, teams, notes and per-file routing. Later, on the same trusted offline browser, explicitly select **all original source files in the identical order** in the handoff shelf, and then use the new **PRIVATE HUMAN review plan re-open** file selector. The input is read locally (strict duplicate-key JSON, bounded 96 KiB, exact required schema and literal false authority flags). Re-opening refuses if any file name, byte length, original unsigned SHA-256, structural classification, count or order has changed, or if HUMAN fields are invalid. Only after an explicit confirmation are all in-memory HUMAN choices restored atomically. The originals remain untouched and no incompatible/partial metadata is copied. This does not authenticate the original source or operator, prove consent or perform a real revocation. The inventory is unencrypted plaintext PRIVATE; store it separately inside the existing original encrypted scope vault if the recipient and format are compatible, and authenticate recipients separately.

## Browser-only package digest (no Python required)

Open **scope-unified-workspace/verify.html** locally, select the received ZIP, and optionally paste its expected SHA-256 from a **separately authenticated, independent source**. The browser calculates SHA-256 with Web Crypto in memory, never uploads any bytes, and never saves data. A digest match is **REVIEW_ONLY**, not the original source, consent or authorization proof. For an actual per-file inventory check use the separate offline Python checker below. The browser falls back to a HOLD notice when Web Crypto is unavailable.

## Inspect a received package without extracting it

On a trusted local machine with Python 3, the independent non-authorizing read-only tool checks the complete ZIP or a **freshly extracted** bundle against its unsigned inventory and exact pinned source-head declarations:

    python3 scope-unified-workspace/check_bundle.py --zip scope-unified-workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip

    python3 scope-unified-workspace/check_bundle.py --directory /path/to/newly-extracted-bundle-root

Successful byte-level transport comparison explicitly returns **REVIEW_ONLY (exit 3)**, never authorization or exit 0. Malformed, incomplete, modified, unexpected, symlinked or unbounded input yields **HOLD (exit 2)**. This cannot authenticate the source: the inventory is unsigned, so an adversary could change both package bytes and manifest. Treat any received package as untrusted until original channel/source and intended recipients are independently verified. This CLI does not extract files, run scripts from the archive, contact anything or read client data.

## Safety and release fence

- Incubate M3/M7 **DRAFT/HOLD**; no merge to main or production deployment.
- No client, operator, engagement or grant is authenticated merely by these copied files or human statements; browser imported source remains untrusted without the **original** backend and separate operator/client identity proof.
- Open security boundaries remain #177 request→grant, #182 consent/revocation and #829 grant tenant integrity, plus current-auth checks at action time.
- Original exact-head **hosted AND permanent registered named-VPS CI**, original source-owner acceptance, independent security/privacy/browser/cryptographic review, real separate up-to-date client/operator consent with revocation at use and explicit HUMAN GO are outstanding.
- No QA/regression/testsuites were created or run under the 17 October execution policy. A successful product build does **not** certify a browser workflow, an authorization or a release.
