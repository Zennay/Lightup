# LightUp · Casebook Change Control (private, read-only)

**Current release state:** INCUBATE M3/M7 · PLAN/LAB ONLY · **DRAFT / HUMAN HOLD**. This is a separate child of [original Casebook + STOP integration](https://github.com/Zennay/Lightup/pull/1624). It grants no main merge, production deployment, live scan, grant, operator approval, revocation, handler or target access.

## Product: human-first authorization history review

The held original authenticated Casebook emits read-only single-tenant historical records for persisted assessment requests, engagements, authorization grants, risk approvals and per-engagement attention. A recorded grant is never a fresh permit. This workspace supplies change-control across all five original families: select two chronological original snapshots; refuse unknown or mismatched tenants, duplicate JSON keys, conflicting source counts, unverified authority flags or malformed records; compare exact original IDs and fields; highlight material changes and missing rows; show a cross-family original engagement-impact board, with urgent source and unacknowledged human follow-ups while leaving tenant-level requests unlinked; assign ephemeral human follow-up stages; export privacy-separated aggregate and private review handoffs. Original records never change.

The fully portable, self-contained browser build is **standalone.html** (one file, embedded script/style with exact SHA-256 CSP). It can be opened as a local offline file without fetching other resources. Its script is placed after the page DOM so initialization can access every screen control. The editable source form has three files: **index.html**, **app.js**, **style.css**. Open index.html from this folder in a modern offline secure-context browser supporting Web Crypto. Its CSP forbids remote scripts, networks, images and fonts. There is no browser persistence; imported data resides in memory only. The two input files are bounded to 512 KiB each, UTF-8/JSON strict and 200 original rows per source family.

## Route A: compare two original PRIVATE Casebook files

From the repository checkout containing the existing held original Casebook, perform a real original DomainStore login. An operator must select exactly one tenant, and a client may access only its own persisted tenant.

    PYTHONPATH=src python3 -m lightup.auth_casebook --database /private/domain.sqlite --email EXISTING_LOGIN --client EXACT_TENANT --output /private/casebook-older.json

At a later authorized human review, export a different exact original source snapshot to a fresh private path:

    PYTHONPATH=src python3 -m lightup.auth_casebook --database /private/domain.sqlite --email EXISTING_LOGIN --client EXACT_TENANT --output /private/casebook-newer.json

Open **scope-change-control/index.html**, select older then newer. Review priority, original IDs, recorded source status transitions before→after, changed source fields and missing/added original membership. Choose *local human stages only*. Export either anonymous aggregate JSON (without tenant, IDs, source timestamps or hashes) or, after separate recipient confirmation, an original-ID-bearing PRIVATE human follow-up JSON. On return, **load the same two original Casebook files** and import that prior PRIVATE browser review via **Restore source-bound human stages**. Restore requires exact old/new SHA-256 byte equality, original times, original tenant, full original changed-ID membership, unchanged source classification/field names and literal human-only stage values. It refuses stale, swapped, incomplete, reclassified or unauthorized packets atomically. A CLI-origin review packet from the current original authenticated refresh/workspace can also be imported in the same control. Its exact old/new original SHA-256 bytes, tenant, original row membership, original changed-field set and original aggregate classifications are checked first; all human stages start unreviewed. A later browser-generated return restores actual human-only stages only when those same source identities match. Neither packet is a grant or signer identity.

## Route B: authenticated fresh observation vs prior original

This CLI avoids manually creating the second Casebook file: it reads a previous original 0600 owner-held, non-symlink regular JSON file and invokes the unchanged original DomainStore authentication/lockout and original Casebook query for the selected tenant. Use an existing real account, and keep the resulting review file private:

    PYTHONPATH=src python3 scope-change-control/refresh.py --database /private/domain.sqlite --email EXISTING_LOGIN --client EXACT_TENANT --previous /private/casebook-older.json --output-private /private/NEW-change-review.json

A client reading its own persisted tenant may omit the client argument. The CLI produces a no-overwrite owner-only 0600 review file and an ID-free aggregate on stdout; **exit 2** means a human-only review packet was created, **exit 3** means HOLD on input/authentication/destination. Exit 0 is deliberately never a permission verdict. The private file includes original identities and changed **field names**, but never the raw previous/current original record bodies. SHA-256 is an unsigned local byte-correlation marker.

## Security, privacy and provenance

The original Casebook and STOP sources may reflect separate historical snapshots: a changed window, deleted grant row, absent STOP, recorded approval or empty comparison is **not** a verified revocation, remediation, live permission or client consent. Source SHA-256 does not authenticate the issuer. A locally acknowledged human task never upgrades an original source decision. No production target, scanner, remote server, database write, new grant or authorization action exists in this module.

Aggregate export omits tenant, IDs, timestamps, fingerprints, targets and private notes. Private export may include original tenant/record IDs and exact source digests: share only through a separately verified private channel. No real client database, source input or live target was used to create this feature. No QA, regression or test suites were added.

## Ownership and release boundary

All newly authored integration files live solely in **scope-change-control/**. This branch also merges the seven unchanged source-owner Scope Window Review files from [PR #1626](https://github.com/Zennay/Lightup/pull/1626) with a two-parent history-preserving merge. No original source-owner paths are edited: original grant source [#1614](https://github.com/Zennay/Lightup/pull/1614), Casebook [#1620](https://github.com/Zennay/Lightup/pull/1620), Casebook/STOP composition [#1624](https://github.com/Zennay/Lightup/pull/1624) and original Scope Window Review [#1626](https://github.com/Zennay/Lightup/pull/1626) remain owned separately.

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

Open the new private directory and follow START-HERE.txt. On a trusted workstation, launch **standalone.html** offline and select **OLDER-ORIGINAL.json** and **NEWER-ORIGINAL.json**. No browser persistence or network transfer occurs. Select the native PRIVATE-review.json in **Restore source-bound human stages** after the original pair has been loaded: its actual original CLI classifications and aggregate are independently recomputed from those two files. All initial human stages remain unreviewed (the original CLI invents no human decisions). After humans edit stages, separately export the browser's PRIVATE file and restore it only against the same exact original source bytes.

For a purely local technical inspection without loading any client data onto a remote service:

    PYTHONPATH=src python3 scope-change-control/workspace_inspect.py \
      --workspace /private/NEW-CASEBOOK-CHANGE-CONTROL

This non-mutating local inspector reads all seven files via no-follow bounded owner-only descriptors, checks the unsigned manifest bytes, re-admits both original Casebook source records, recomputes the native original change mapping and verifies the exact private review and anonymous aggregate. It outputs **only privacy-minimal aggregate figures**, always exit **2 (HOLD_HUMAN_REVIEW)** for a coherent local package or exit **3 (HOLD)** for incomplete/inconsistent source. A successful technical read is neither an independent security review, an audit signature, an authentic client agreement nor a release gate.

**Important:** the original source snapshots were recorded at different times and the current export is not an action-time authorization/STOP decision. Always use the actual original at-use revocation, client/operator consent and execution gateway before any production work. None of these new modules issues a grant, contacts a target, scans or writes the original domain database.

## Private human follow-up fields

The operator source-delta table now offers **Add follow-up** for each actual changed original source row. The offline dialog accepts a bounded self-declared reviewer alias, next human action, private note and optional exact UTC calendar day. Inputs are never written to original DomainStore, browser storage or a remote service. These human fields do **not** identify an authenticated person or approve any source decision. A team must independently verify the recipient before clicking the existing PRIVATE export confirmation.

The browser now stores human-only fields in an exact original-source-bound private export, and the private return restores them atomically only when both original source bytes, tenant, original membership, changed field names, human stage and the source-change classification still match. The anonymous aggregate never includes these note fields. A native CLI review starts with deliberately empty human fields and an unreviewed stage. Missing, stale or changed source records cannot inherit old notes automatically.
## Route D: one-account consolidated Scope Operations Room (three real offline operator apps)

This branch now physically integrates the original held [Scope Window Review #1626](https://github.com/Zennay/Lightup/pull/1626) and original held [Casebook/STOP #1624](https://github.com/Zennay/Lightup/pull/1624). The source-owner Window Review seven files are exact original Git blobs on a two-parent merge. Original owner branches remain untouched.

The new combined_room.py makes one authentic original DomainStore account read and builds two separate private offline product workspaces from the SAME newly authenticated original Casebook snapshot: Change Control (historic changes and private human actions), original Window Review (recorded grant windows and generic identity-free UTC reminders), and original Engagement Inbox (every engagement including those with NO recorded grants and pending risk review). It creates a third static one-file navigation launchpad OPEN-ROOM.html for those three applications, and a top-level private COMPLETE-MANIFEST.json last after the two original child manifests. Nothing in this room is a live permission decision.

From the repository checkout, with an older authentic owner-private 0600 Casebook JSON and a real original account:

    umask 077
    PYTHONPATH=src python3 scope-change-control/combined_room.py \
      --database /private/domain.sqlite --email EXISTING_ACCOUNT \
      --client EXACT_ORIGINAL_TENANT \
      --previous /private/OLDER-ORIGINAL.json \
      --room /private/NEW-LIGHTUP-SCOPE-ROOM \
      --lead-days 7 --future-days 45 --daily-capacity 8

An original client account can omit --client; an operator must select exactly one original tenant. The password is an interactive original-account password prompt (never written into a file or command). Output must be a NEW owner-only directory under a trusted parent that is not group/world writable. Every child private file is mode 0600 and each private directory mode 0700. The runner calls unchanged original Window Review only with its offline --casebook input, never a second DB login or grant, STOP or target operation. Ordinary publication errors clean the own new private directory and never overwrite another location. Do not infer live STOP clearance from an absence of a recorded STOP.

The private room contains the original Newer/Older source, private human review, anonymous aggregate and standalone Change Control in change-control/; the original owner Window Review human-review board, every-engagement inbox, private agenda, generic .ics calendar and manifest in window-review/; plus the scriptless OPEN-ROOM.html, READ-FIRST.txt and private COMPLETE-MANIFEST.json at the root. Open the launchpad locally on an authorized offline workstation. The independent Window Review and Change Control private files remain local; do not upload the directory or reuse its source hashes as authority.

Receiving-person read-only technical check:

    PYTHONPATH=src python3 scope-change-control/combined_inspect.py \
      --room /private/NEW-LIGHTUP-SCOPE-ROOM

The combined inspector reuses both actual original product inspectors, verifies both child manifests, byte-equal current Casebook records, and the static launchpad/room manifest. It outputs privacy-minimal figures only. Exit 2 means technically coherent HISTORIC HUMAN HOLD, exit 3 means invalid/incomplete HOLD. Neither means authentication, authorization, current consent, revocation, successful scan or release. It never contacts a target or mutates the original domain.

All original release requirements remain: exact-head original hosted plus permanently registered named VPS CI, independent source-owner/security/privacy review, genuine separate authenticated client/operator consent with action-time revocation, original #177/#182/#829 and explicit HUMAN GO. This is DRAFT/HOLD, NOT deployed and NOT merged to main.
### Entirely offline room from two previously exported original private sources

For authorized human review when the original DomainStore is not available, the *same* three-app room can be built from **two separately collected genuine original PRIVATE Casebook source JSON exports**. This does **not** perform a current login or confirm that the original grants, risks or STOP state are still current:

    umask 077
    PYTHONPATH=src python3 scope-change-control/combined_room.py \
      --previous /private/OLDER-ORIGINAL.json \
      --current-casebook /private/NEWER-ORIGINAL.json \
      --room /private/NEW-OFFLINE-SCOPE-OPERATIONS-ROOM \
      --lead-days 7 --future-days 45 --daily-capacity 8

This mutually exclusive source mode deliberately rejects --database, --email and --client selectors. Both user-provided original files must already be non-symlink, owner-0600, bounded original Casebook snapshots; both are admitted and compared before publication, with exact original source bytes preserved. All authority/source-verification flags stay FALSE. The original window owner CLI consumes only the exact same newer source via its local, offline --casebook mode. The generated human board and calendar are based on a historical snapshot, not a current permit.

Authenticated original-account mode remains the default route for a fresh observation; offline-file mode is a read-only fallback for physically separated review. Never label an offline source comparison as an authenticated new consent or live STOP check. Both produce HUMAN HOLD-only private files and neither enables targets, grants, scanners or deployment.
## Recorded request-to-grant dependency attention (integrated in Change Control)

The operator browser now renders a dedicated **original request → grant dependency board** using only original Casebook snapshots. It surfaces every changed/new/missing original grant source row, original source HOLD/missing request references and, critically, **unchanged original grants whose explicitly recorded approved_request_id points to an assessment request that was changed or removed between two original Casebook snapshots**. The original grant itself may look unchanged, but its recorded original request provenance needs human reinspection. No new inferred engagement or request association is invented: each relationship comes from the literal grant.approved_request_id in original source.

Every private dependency row shows original grant identity, recorded engagement, recorded request reference and original request status before→after, original source link observation and human attention reasons. Human reviewers can assign a local human stage, self-reported reviewer alias, next action, private note and optional UTC due date. The private handoff includes the complete source-bound dependency group and human actions; its import rederives exact source membership and every original field from both original SHA-256-pinned snapshots **before atomically restoring any human-only stage or note**. An anonymous aggregate contains only aggregate dependency/stage counts, not original IDs or note text. No browser storage, uploads, grants, new request status, STOP writes, execution or current consent inference.

The original authenticated native refresh CLI now also computes a new **unchanged_grant_request_dependencies** private row collection and an ID-free **linked_unchanged_grant_attention_count**. The new CLI fields are independently source-recomputed by the browser import. Older CLI packets without BOTH fields remain readable for human source comparison, but never claim to contain the new dependency report. Native CLI items begin UNREVIEWED and never invent real human owner decisions. All resulting statuses remain HUMAN HOLD.

This is a product fix for hidden follow-ups across a linked unchanged grant, not permission validation. A recorded approved_request_id, an old 'approved' request or a locally acknowledged human action NEVER supplies a valid grant or bypasses the original execution gateway. Source owner #1624, original #1626 and all original grant/STOP/authorization paths remain untouched.