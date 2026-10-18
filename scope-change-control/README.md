# LightUp · Casebook Change Control (private, read-only)

**Current release state:** INCUBATE M3/M7 · PLAN/LAB ONLY · **DRAFT / HUMAN HOLD**. This is a separate child of [original Casebook + STOP integration](https://github.com/Zennay/Lightup/pull/1624). It grants no main merge, production deployment, live scan, grant, operator approval, revocation, handler or target access.

## Product: human-first authorization history review

The held original authenticated Casebook emits read-only single-tenant historical records for persisted assessment requests, engagements, authorization grants, risk approvals and per-engagement attention. A recorded grant is never a fresh permit. This workspace supplies change-control across all five original families: select two chronological original snapshots; refuse unknown or mismatched tenants, duplicate JSON keys, conflicting source counts, unverified authority flags or malformed records; compare exact original IDs and fields; highlight material changes and missing rows; assign ephemeral human follow-up stages; export privacy-separated aggregate and private review handoffs. Original records never change.

The fully portable, self-contained browser build is **standalone.html** (one file, embedded script/style with exact SHA-256 CSP). It can be opened as a local offline file without fetching other resources. Its script is placed after the page DOM so initialization can access every screen control. The editable source form has three files: **index.html**, **app.js**, **style.css**. Open index.html from this folder in a modern offline secure-context browser supporting Web Crypto. Its CSP forbids remote scripts, networks, images and fonts. There is no browser persistence; imported data resides in memory only. The two input files are bounded to 512 KiB each, UTF-8/JSON strict and 200 original rows per source family.

## Route A: compare two original PRIVATE Casebook files

From the repository checkout containing the existing held original Casebook, perform a real original DomainStore login. An operator must select exactly one tenant, and a client may access only its own persisted tenant.

    PYTHONPATH=src python3 -m lightup.auth_casebook --database /private/domain.sqlite --email EXISTING_LOGIN --client EXACT_TENANT --output /private/casebook-older.json

At a later authorized human review, export a different exact original source snapshot to a fresh private path:

    PYTHONPATH=src python3 -m lightup.auth_casebook --database /private/domain.sqlite --email EXISTING_LOGIN --client EXACT_TENANT --output /private/casebook-newer.json

Open **scope-change-control/index.html**, select older then newer. Review priority, original IDs, recorded source status transitions before→after, changed source fields and missing/added original membership. Choose *local human stages only*. Export either anonymous aggregate JSON (without tenant, IDs, source timestamps or hashes) or, after separate recipient confirmation, an original-ID-bearing PRIVATE human follow-up JSON. On return, **load the same two original Casebook files** and import that prior PRIVATE browser review via **Restore source-bound human stages**. Restore requires exact old/new SHA-256 byte equality, original times, original tenant, full original changed-ID membership, unchanged source classification/field names and literal human-only stage values. It refuses stale, swapped, incomplete, reclassified or unauthorized packets atomically. A CLI-origin review packet is a different one-way operator format and is not silently treated as a browser review.

## Route B: authenticated fresh observation vs prior original

This CLI avoids manually creating the second Casebook file: it reads a previous original 0600 owner-held, non-symlink regular JSON file and invokes the unchanged original DomainStore authentication/lockout and original Casebook query for the selected tenant. Use an existing real account, and keep the resulting review file private:

    PYTHONPATH=src python3 scope-change-control/refresh.py --database /private/domain.sqlite --email EXISTING_LOGIN --client EXACT_TENANT --previous /private/casebook-older.json --output-private /private/NEW-change-review.json

A client reading its own persisted tenant may omit the client argument. The CLI produces a no-overwrite owner-only 0600 review file and an ID-free aggregate on stdout; **exit 2** means a human-only review packet was created, **exit 3** means HOLD on input/authentication/destination. Exit 0 is deliberately never a permission verdict. The private file includes original identities and changed **field names**, but never the raw previous/current original record bodies. SHA-256 is an unsigned local byte-correlation marker.

## Security, privacy and provenance

The original Casebook and STOP sources may reflect separate historical snapshots: a changed window, deleted grant row, absent STOP, recorded approval or empty comparison is **not** a verified revocation, remediation, live permission or client consent. Source SHA-256 does not authenticate the issuer. A locally acknowledged human task never upgrades an original source decision. No production target, scanner, remote server, database write, new grant or authorization action exists in this module.

Aggregate export omits tenant, IDs, timestamps, fingerprints, targets and private notes. Private export may include original tenant/record IDs and exact source digests: share only through a separately verified private channel. No real client database, source input or live target was used to create this feature. No QA, regression or test suites were added.

## Ownership and release boundary

All new files live solely in **scope-change-control/**. No original source-owner paths are changed: original grant source [#1614](https://github.com/Zennay/Lightup/pull/1614), Casebook [#1620](https://github.com/Zennay/Lightup/pull/1620), Casebook/STOP composition [#1624](https://github.com/Zennay/Lightup/pull/1624) and original Scope Window Review [#1626](https://github.com/Zennay/Lightup/pull/1626) remain owned separately.

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. DO NOT MERGE TO MAIN OR DEPLOY** before original exact-head hosted + permanently registered named VPS CI, original source-owner acceptance, independent security/privacy review, separately authenticated actual client/operator consent, real action-time revocation, canonical #177/#182/#829 execution-gate integration and explicit HUMAN GO.


## Route C: one-command **complete private offline review workspace**

Run the optional native **workspace.py** using only the previously exported **original** owner-private 0600 Casebook JSON and an actual existing DomainStore account. The output directory must not exist; its parent must be a trusted, non-group/other-writable directory. No source writing or browser network access is involved.

    PYTHONPATH=src python3 scope-change-control/workspace.py \
      --database /private/domain.sqlite \
      --email EXISTING_LOGIN \
      --client EXACT_TENANT \
      --previous /private/casebook-older.json \
      --workspace /private/NEW-CASEBOOK-CHANGE-CONTROL

The tool prompts for the existing original account password (never via command-line argument), applies the original account lockout and tenant-selection rules, reopens the previous real private Casebook JSON with a no-follow descriptor and SHA-256 drift check, builds a fresh original current Casebook observation and creates exactly one new private mode-0700 directory. It publishes these owner-only mode-0600 files in that new directory, **manifest last**:

- **OLDER-ORIGINAL.json**: the original previous file's exact authenticated historical source bytes, unchanged.
- **NEWER-ORIGINAL.json**: freshly authenticated original Casebook source, no synthesized approvals.
- **PRIVATE-review.json**: CLI-native source-diff dossier with original IDs and changed *field names* but never both raw original record bodies. Human review only.
- **aggregate.json**: no original IDs/tenant, source times, digests or private field values.
- **standalone.html**: complete offline operator interface; no remote scripts or assets.
- **START-HERE.txt**: precise human workflow and explicit non-authorization warnings.
- **manifest.json**: unsigned original-byte SHA-256 and byte length for every other file, written last after each file is flushed and fsynced.

The tool refuses existing output destinations, symbolically linked source files, malformed/changed previous sources, unadmitted current tenants, oversized sources or incomplete original relations. An ordinary incomplete write cleans its *newly created* directory. A sudden power loss may still require a human to remove an incomplete private folder; a directory appearing on disk is never evidence that an export completed. The file manifest is deliberately **unsigned** and not proof of authenticated issuer, current account, tenant consent or permission.

Open the new private directory and follow START-HERE.txt. On a trusted workstation, launch **standalone.html** offline and select **OLDER-ORIGINAL.json** and **NEWER-ORIGINAL.json**. No browser persistence or network transfer occurs. The initial native PRIVATE-review.json is intentionally a CLI dossier, not a fabricated human-stage return. After humans edit stages, separately export the browser's PRIVATE file and restore it only against the same exact original source bytes.

For a purely local technical inspection without loading any client data onto a remote service:

    PYTHONPATH=src python3 scope-change-control/workspace_inspect.py \
      --workspace /private/NEW-CASEBOOK-CHANGE-CONTROL

This non-mutating local inspector reads all seven files via no-follow bounded owner-only descriptors, checks the unsigned manifest bytes, re-admits both original Casebook source records, recomputes the native original change mapping and verifies the exact private review and anonymous aggregate. It outputs **only privacy-minimal aggregate figures**, always exit **2 (HOLD_HUMAN_REVIEW)** for a coherent local package or exit **3 (HOLD)** for incomplete/inconsistent source. A successful technical read is neither an independent security review, an audit signature, an authentic client agreement nor a release gate.

**Important:** the original source snapshots were recorded at different times and the current export is not an action-time authorization/STOP decision. Always use the actual original at-use revocation, client/operator consent and execution gateway before any production work. None of these new modules issues a grant, contacts a target, scans or writes the original domain database.
