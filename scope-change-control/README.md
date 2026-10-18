# LightUp · Casebook Change Control (private, read-only)

**Current release state:** INCUBATE M3/M7 · PLAN/LAB ONLY · **DRAFT / HUMAN HOLD**. This is a separate child of [original Casebook + STOP integration](https://github.com/Zennay/Lightup/pull/1624). It grants no main merge, production deployment, live scan, grant, operator approval, revocation, handler or target access.

## Product: human-first authorization history review

The held original authenticated Casebook emits read-only single-tenant historical records for persisted assessment requests, engagements, authorization grants, risk approvals and per-engagement attention. A recorded grant is never a fresh permit. This workspace supplies change-control across all five original families: select two chronological original snapshots; refuse unknown or mismatched tenants, duplicate JSON keys, conflicting source counts, unverified authority flags or malformed records; compare exact original IDs and fields; highlight material changes and missing rows; assign ephemeral human follow-up stages; export privacy-separated aggregate and private review handoffs. Original records never change.

The browser app has three files: **index.html**, **app.js**, **style.css**. Open index.html from this folder in a modern offline secure-context browser supporting Web Crypto. Its CSP forbids remote scripts, networks, images and fonts. There is no browser persistence; imported data resides in memory only. The two input files are bounded to 512 KiB each, UTF-8/JSON strict and 200 original rows per source family.

## Route A: compare two original PRIVATE Casebook files

From the repository checkout containing the existing held original Casebook, perform a real original DomainStore login. An operator must select exactly one tenant, and a client may access only its own persisted tenant.

    PYTHONPATH=src python3 -m lightup.auth_casebook --database /private/domain.sqlite --email EXISTING_LOGIN --client EXACT_TENANT --output /private/casebook-older.json

At a later authorized human review, export a different exact original source snapshot to a fresh private path:

    PYTHONPATH=src python3 -m lightup.auth_casebook --database /private/domain.sqlite --email EXISTING_LOGIN --client EXACT_TENANT --output /private/casebook-newer.json

Open **scope-change-control/index.html**, select older then newer. Review priority, original IDs, changed source fields and missing/added original membership. Choose *local human stages only*. Export either anonymous aggregate JSON (without tenant, IDs, source timestamps or hashes) or, after separate recipient confirmation, an original-ID-bearing PRIVATE human follow-up JSON.

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
