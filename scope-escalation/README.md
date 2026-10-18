# LightUp · Scope Escalation Board

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a strictly offline, human-only operations companion for the **original authenticated** Casebook source (held [#1620](https://github.com/Zennay/Lightup/pull/1620)). Not an authorization or deployment approval.

## What users can do

- Turn one previously password-authenticated, one-tenant `lightup.auth_casebook.v1` source export into a readable **human escalation queue** for engagements and pending/rejected client requests. Source HOLD/provenance conflicts rise above pending and ordinary manual reviews; historically stored grants are **never** classified as permission.
- Inspect each engagement's exact original grant-link/window and risk-decision observations; search original identifiers and filter HOLD/PENDING/REVIEW.
- Assign self-declared human reviewers, next actions, stages and tentative UTC follow-up dates entirely offline in browser memory.
- Bulk-select visible source-bound follow-ups, confirm HUMAN-only changes to self-declared reviewer, stage and proposed due date, and preserve already edited notes by default. See the live offline reviewer workload count. New records default to **unassigned**, never completed or approved.
- Export a separately confirmed **PRIVATE** original-ID-bearing source SHA-256-bound human review return, or restore only against the same exact source snapshot and complete source row/order/attention identity. Invalid or partial imports preserve existing edits.
- Download ID-free anonymous aggregate counts by review tier and human stage, or use the private CSV in the workspace to coordinate follow-ups.

- **Separate PRIVATE recipient workflow:** choose one self-declared reviewer and select 1–200 original Casebook follow-ups. Export `PRIVATE-scope-reviewer-handoff.json` including only selected original IDs, source-bound historical observations, original human baseline and proposed human next actions. No other tenant cases are included. Send this **and the source-free** `PRIVATE-recipient-desk.html` from the output workspace through an independently verified PRIVATE channel.
- The recipient opens `PRIVATE-recipient-desk.html` offline, imports the selected handoff, edits only **human stage, proposed due date and private next action**, then exports `PRIVATE-scope-reviewer-reply.json`. The original reviewer alias cannot be changed through this editor; it is self-declared and is never authenticated identity or consent.
- The operator keeps the original board open, or selects **Register saved reviewer handoff** to re-establish the exact saved packet after reopening the original source. Use **Preview + apply PRIVATE reviewer reply** to see before→after human changes. Only when the original source hash, tenant, source observations, packet identity, row set, reviewer, row order and **every current human baseline** still match are all human edits applied atomically. A changed/stale/incomplete/partial reply holds without overwriting the operator's current notes.
- Source bound handoff/reply and unsigned packet identity are **not sender authentication**. Independently verify who receives/sends the files. There is no client consent, risk approval, grant, STOP check, execution or scanner capability in either app. When the selected recipient has not been verified, **do not share the packet**.


## Generate the complete offline workspace

First use the **unchanged original** Casebook source-owner tool to authenticate with a real existing account and export a tenant-specific PRIVATE JSON to a file readable only by its owner (mode 0600). Do not copy client data into source control or chat.

From a private trusted local terminal in the held original-source checkout:

```sh
umask 077
PYTHONPATH=src python3 -m lightup.auth_casebook --help
python3 scope-escalation/board.py \
  --source /private/ORIGINAL-casebook.json \
  --workspace /private/NEW-scope-escalation-room
```

### Alternative: direct existing-account login (no intermediate source export)

For an original persisted LightUp account, this command uses the **unchanged original** `authenticated_casebook` source and tenant/lockout policy. The password is requested interactively from the terminal, never in CLI args or config. It builds a private room directly from that one original snapshot without writing a second plaintext source file:

```sh
umask 077
PYTHONPATH=src python3 scope-escalation/authenticated_workspace.py \
  --database /private/ORIGINAL-domain.sqlite \
  --email EXISTING-LIGHTUP-ACCOUNT \
  --client EXACT-CLIENT-ID \
  --workspace /private/NEW-original-authenticated-room
```

An original client account may omit `--client`; an operator must select a real permitted client ID. Interactive authentication can mutate **original account lockout metadata** as designed; this companion never changes grants, requests, risks, STOP, source rows, scans or worker state. The generated standalone HTML is still private and **does not verify action-time revocation or independent client consent**.

### Human reviewer collaboration, with private least-necessary disclosure

1. Use the operator PRIVATE board to assign a single self-declared reviewer to the selected original engagements/requests and optionally filter HOLD/PENDING. Mark the relevant checkboxes, then export **selected PRIVATE reviewer handoff**. A recipient gets only chosen IDs, historical original source notices and local human actions; it does not receive the entire Casebook, a password or any action authority.
2. Verify the actual recipient through a trusted private channel, then share the packet and **PRIVATE-recipient-desk.html** (the latter is source-free). Never publish either packet or private board to the internet.
3. The recipient imports the JSON in its standalone offline HTML, makes human-only updates and exports **PRIVATE-scope-reviewer-reply.json**. A proposed `human_followup_complete` means *self-declared administrative follow-up*, **not** security remediation, consent, grant, revocation or target approval.
4. The operator selects **Preview + apply PRIVATE reviewer reply** in the original board. It requires the original issued packet to remain in browser RAM; if the operator tab was closed, first use **Register saved reviewer handoff** to import the exact earlier exported JSON into the same unchanged original source revision and baseline. Modified or missing original review state causes HOLD; no partial changes are applied. Human notes must then be preserved with the board's standard PRIVATE review export.

No signed or separately authenticated recipient identity is created by the exchange. Packet IDs are local correlation only; checksums are not sender proof. No session, tenant, source row or safety authority is updated. Recipient reply files contain original IDs and private human notes; keep them at the same sensitivity level as the handoff.

### Recipient source-bound inspection

If a recipient already has the exact previously authenticated original PRIVATE Casebook JSON from an independently verified channel, they can inspect an offline package before opening it:

```sh
python3 scope-escalation/workspace_inspect.py \
  --source /private/ORIGINAL-casebook.json \
  --workspace /private/RECEIVED-scope-room
```

This read-only recipient command checks every expected file byte against independently recomputed source artifacts, rejects unsafe mode/symlink/directory inventory and checks the unsigned final manifest. It returns **2 REVIEW_ONLY** when locally coherent or **3 HOLD** when inconsistent, never 0/authority. The optional direct-login route does not automatically save original source JSON; obtain an **independently authenticated** equivalent exact original source file if later inspection by another recipient is required. Matching SHA-256 bytes are not a signature or proof of sender/recipient authority.

The workspace **must not exist**. Its parent must not be writable by group/others. The builder uses Python's standard library, rejects symlink or group-readable original files, BOM, duplicate JSON keys, nonfinite JSON, unsupported source versions, false-authority contradictions, duplicate record identities, incomplete engagement cases and contradictory original counts. It creates a mode 0700 directory with these mode 0600 files (including the new recipient desk):

- `PRIVATE-recipient-desk.html`: source-free private recipient handoff/reply app; SHA-pinned self-contained CSS/JS, no network or persistent storage. Send separately only after recipient verification.
- `PRIVATE-board.html`: standalone browser UI with inline SHA-256 pinned scripts/styles and Content Security Policy `connect-src 'none'`; contains tenant, original IDs and historical source observations.
- `PRIVATE-queue.csv`: private original IDs and human action suggestions; formula-escaped on export (including Unicode-obscured leading formulas), though recipients should still use a restricted spreadsheet viewer.
- `aggregate.json`: no original identifiers, tenant, timestamps, notes or source hash.
- `START-HERE.txt`: workflow and permissions warning.
- `manifest.json`: unsigned exact file hashes and byte lengths, written last.

Open `PRIVATE-board.html` on a trusted offline workstation. No web service, fetch, browser local storage, target request, scanner, domain mutation, account sign-in, grant minting or execution is present in this companion. Browser human notes are transient until PRIVATE export. Export/restore performs all-or-nothing source identity checks; matching hashes are **not** proof of signer/recipient identity or live source freshness.

A normal completed **human-only** build exits `2 / REVIEW_ONLY`; refusal exits `3 / HOLD`. Neither exit is permission. Only a separate current original production admission flow can evaluate authentic client/operator consent, grant provenance, STOP/at-use revocation, scope, current risk and legitimate authorization, with independent security and privacy gates.

## Source and ownership boundary

New `scope-escalation/` files only, based on immutable original Casebook owner commit `fa3a260234daa1178b5f6e4fc95cbd36e12d61fd`. Do not modify active #177/#673/#829 original source owners, held STOP, Casebook/Impact/Change Control branches, CI, QA, runtime or target scanner. No merge to `main`, deploy or active work before original exact-head hosted and permanent named VPS CI, original owner acceptance, independent security/privacy approvals, authentic independently authenticated client/operator consent with action-time revocation and explicit HUMAN GO. Historical or missing rows NEVER imply verified revocation or remediation.
