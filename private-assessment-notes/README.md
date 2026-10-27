# LightUp · PRIVATE credential-masked HUMAN assessment notes

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Complete local, non-authorizing HUMAN review product on the original Basic/Bearer/API-key credential redaction boundary. No target interaction, scan, model invocation, upload, customer notification, approval, deployment, retest, or release.

## What this does

The existing central `lightup.redaction.redact_text()` now includes the **unchanged original producer patch** from draft [PR #672](https://github.com/Zennay/Lightup/pull/672) for `Authorization: Basic ...` and `Proxy-Authorization: Basic ...`, alongside existing Bearer, AWS access key and generic token/password patterns. Original source-owner branch untouched. The utility **does not claim to detect all secrets, anonymize data, erase personal information, or make material safe to share**.

This independent, original-source-driven application:

1. Accepts **1–12 individually selected existing owner-private UTF-8 notes** (each at most 512 KiB; overall 2 MiB), without filesystem discovery. Symlink, special file, non-owner input, group/world-readable file, corrupt text and oversize source refuse with HOLD.
2. Invokes unchanged installed original `redact_text()` on the selected text only, without transmitting any bytes to a model, server, target or analytics platform.
3. Creates a **fresh private 0700 directory** outside the repository with owner-only 0600 credential-masked text files, readable scriptless local HTML summary, unsigned exact-source SHA/size manifest with only source ordinals (never source filenames), an original-source-bound editable HUMAN CSV, and an **offline interactive HUMAN browser editor** with a SHA-256 CSP-pinned inline script and no network/storage.
4. The browser lets an operator choose exactly one of `NEEDS_HUMAN_REVIEW`, `SOURCE_OWNER_REQUIRED`, `WITHHOLD`, or `INTERNAL_REVIEW_ONLY` for each original source and add a bounded brief internal note. It downloads a PRIVATE CSV locally. Even `INTERNAL_REVIEW_ONLY` never means external clearance.
5. A separate explicit `finalize` command reopens the unchanged original workroom, rejects edited source-bound SHA/byte metadata and replaced redacted note bytes, reads the complete original-bound HUMAN CSV, and creates a *second* fresh owner-private HUMAN packet with decisions, originals' **masked only** note copies, combined internal notes, static readable HTML, and unchanged literal-false authority flags.
6. The final stage deliberately returns **HOLD (code 3)** even when its local HUMAN packet was correctly written: there is **never** a release verdict, client consent or verified masking claim. Preparation returns **REVIEW_ONLY (code 2)**. Neither is a successful authorization code.

## Run locally

Requirements: Python 3.11+ and this LightUp checkout. No pip, service, credentials or network.

~~~sh
mkdir -m 700 -p /private/operator-lightup-work
chmod 600 /private/first-private-note.txt /private/second-private-note.txt

python3 private-assessment-notes/notes.py prepare \
  --source /private/first-private-note.txt \
  --source /private/second-private-note.txt \
  --private-parent /private/operator-lightup-work
~~~

Open the printed `OPEN-PRIVATE.html` locally, and follow the link to **PRIVATE offline interactive HUMAN decision editor**. Download the resulting PRIVATE decision CSV. Never put it on an open shared drive.

~~~sh
python3 private-assessment-notes/notes.py finalize \
  --original-kit /private/operator-lightup-work/PRIVATE-lightup-notes-<actual-id> \
  --decisions /private/operator-lightup-work/PRIVATE-HUMAN-decisions-completed.csv \
  --private-parent /private/operator-lightup-work
~~~

The second workroom offers `PRIVATE-HUMAN-summary.html`, individual and combined masked notes, unsigned original-source manifest and completed HUMAN decisions. **The browser/editor does not perform finalize, assessment or any automatic outward action.**

The source file content is never included in either output; **the redacted content may still be highly sensitive**. Original source hashes are not independent provenance or integrity signatures, and source identity cannot establish authorization.

### Workflow and release boundaries

- This is **PRIVATE internal triage only**. Do not post the masked output or manifest to a public issue, PR, Notion page, website, email, or unapproved recipient.
- Pattern redaction cannot prove absence of credentials, secrets, PII or proprietary client evidence; every original needs independent HUMAN privacy review.
- The original #672 fix is selectively composed, not merged to `main` or released. The original owner's production source and review remain separate.
- No QA/test suite added, modified or executed as part of this companion. Native Python syntax/build inspection and source inspection are the only checks made in this lane.
- Original exact-head hosted + permanently registered named VPS CI, original source-owner and independent privacy/security reviews, #177/#182/#829, authenticated separately current client/operator consent with action-time revocation, and explicit HUMAN GO remain release gates. No production merge/deploy.

## Source ownership

This lane is exclusively `private-assessment-notes/` plus the **exact original** `src/lightup/redaction.py` fix from [PR #672](https://github.com/Zennay/Lightup/pull/672). It does **not** alter the concurrently active [assessment-integrated-suite PR #1688](https://github.com/Zennay/Lightup/pull/1688), any active source-authority owner, assessment executor, domain state, auth policy, persistence, runner, CI, test path or third-party repo. The original author PR is not silently claimed as complete.

**CSV safety:** PRIVATE human notes beginning with a spreadsheet formula prefix
(`=`, `+`, `-`, or `@`, even after whitespace) are rejected in
both the browser export and native finalize. Do not open untrusted CSV with
spreadsheet macros or auto-link execution enabled.

## NEW: retain PRIVATE human decisions across offline revisions

A complete HUMAN decision packet can be reopened **without any original unmasked
source data** and without modifying the earlier packet. The source-bound stage
history and the exact locally masked content are preserved in a new exclusive
private directory. The original full HUMAN CSV receives its own unsigned SHA-256
digest on first `finalize`; reopening demands the original content digest and
HUMAN stage counters match before anything is prepared.

~~~sh
python3 private-assessment-notes/revision.py \
  --prior-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<actual-id> \
  --private-parent /private/operator-lightup-work
~~~

The reopened package contains a fully offline browser Studio prefilled with the
prior human decisions, its own source-byte bound PRIVATE manifest, and the
unchanged redacted-only note bytes. A human can revise stages and notes in the
local browser, export another PRIVATE CSV and deliberately `finalize` another
separate packet. `revision_level` is capped at 32. Original packet and masked
bytes are never overwritten, and old HUMAN recommendations are not silently
carried into authorization or release. Manifest hashes are unsigned local
integrity identifiers only; they are not trusted producer signatures. The
reopen step always reports REVIEW_ONLY and finalization always remains HOLD.
