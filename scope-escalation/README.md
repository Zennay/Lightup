# LightUp · Scope Escalation Board

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a strictly offline, human-only operations companion for the **original authenticated** Casebook source (held [#1620](https://github.com/Zennay/Lightup/pull/1620)). Not an authorization or deployment approval.

## What users can do

- Turn one previously password-authenticated, one-tenant `lightup.auth_casebook.v1` source export into a readable **human escalation queue** for engagements and pending/rejected client requests. Source HOLD/provenance conflicts rise above pending and ordinary manual reviews; historically stored grants are **never** classified as permission.
- Inspect each engagement's exact original grant-link/window and risk-decision observations; search original identifiers and filter HOLD/PENDING/REVIEW.
- Assign self-declared human reviewers, next actions, stages and tentative UTC follow-up dates entirely offline in browser memory.
- Export a separately confirmed **PRIVATE** original-ID-bearing source SHA-256-bound human review return, or restore only against the same exact source snapshot and complete source row/order/attention identity. Invalid or partial imports preserve existing edits.
- Download ID-free anonymous aggregate counts by review tier and human stage, or use the private CSV in the workspace to coordinate follow-ups.

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

The workspace **must not exist**. Its parent must not be writable by group/others. The builder uses Python's standard library, rejects symlink or group-readable original files, BOM, duplicate JSON keys, nonfinite JSON, unsupported source versions, false-authority contradictions, duplicate record identities, incomplete engagement cases and contradictory original counts. It creates a mode 0700 directory with these mode 0600 files:

- `PRIVATE-board.html`: standalone browser UI with inline SHA-256 pinned scripts/styles and Content Security Policy `connect-src 'none'`; contains tenant, original IDs and historical source observations.
- `PRIVATE-queue.csv`: private original IDs and human action suggestions; **not suitable for direct spreadsheet execution** without a separate CSV formula-safety viewer.
- `aggregate.json`: no original identifiers, tenant, timestamps, notes or source hash.
- `START-HERE.txt`: workflow and permissions warning.
- `manifest.json`: unsigned exact file hashes and byte lengths, written last.

Open `PRIVATE-board.html` on a trusted offline workstation. No web service, fetch, browser local storage, target request, scanner, domain mutation, account sign-in, grant minting or execution is present in this companion. Browser human notes are transient until PRIVATE export. Export/restore performs all-or-nothing source identity checks; matching hashes are **not** proof of signer/recipient identity or live source freshness.

A normal completed **human-only** build exits `2 / REVIEW_ONLY`; refusal exits `3 / HOLD`. Neither exit is permission. Only a separate current original production admission flow can evaluate authentic client/operator consent, grant provenance, STOP/at-use revocation, scope, current risk and legitimate authorization, with independent security and privacy gates.

## Source and ownership boundary

New `scope-escalation/` files only, based on immutable original Casebook owner commit `fa3a260234daa1178b5f6e4fc95cbd36e12d61fd`. Do not modify active #177/#673/#829 original source owners, held STOP, Casebook/Impact/Change Control branches, CI, QA, runtime or target scanner. No merge to `main`, deploy or active work before original exact-head hosted and permanent named VPS CI, original owner acceptance, independent security/privacy approvals, authentic independently authenticated client/operator consent with action-time revocation and explicit HUMAN GO. Historical or missing rows NEVER imply verified revocation or remediation.
