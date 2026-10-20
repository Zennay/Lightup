# LightUp · unified PRIVATE scope operator workroom

**Status: INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. Not approved for live use.**

This branch composes four **existing independently owned** scope-authorization companion workrooms into one portable offline package, preserving their exact source bytes. It adds only a navigation hub, offline packaging, unsigned file inventory and operator instructions. It does **not** integrate or promote the original source-owner authorization engine, alter grants, verify client identity, dispatch work, contact a target, modify CI or produce security findings.

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

This is a **snapshot**, not ongoing automatic propagation. Parent source-owner PRs and their branches stay untouched. Changes to those originals need a separately reviewed composition and a new frozen inventory. Duplicated or older assets must never be represented as current original authorization truth.

## Rebuild portable package (product build only)

Run on a trusted local/offline developer checkout:

```sh
python3 scope-unified-workspace/build.py
```

This deterministic Python-stdlib build generates `index.html`, `SOURCE-MANIFEST.json` and `LightUp-Scope-Offline-DRAFT-HOLD.zip`. The manifest lists file sizes, SHA-256 digests and original parent commits for **transport comparison only**. It is **unsigned**, not an independent proof of original authorship, authorized source, tenant identity, runtime behavior or security correctness. The ZIP has fixed metadata and is assembled atomically. It contains no data provided by an operator, browser session, account, customer or database.

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
