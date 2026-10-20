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


## New PRIVATE human review board and selected internal discussion packets

The generated `PRIVATE-HUMAN-editor.html` now includes an in-page private
pattern-masked original note viewer (collapsed by default), local source-position
and note search, a stage filter, visible/all-source counters, and explicit
confirmed bulk HUMAN discussion stages with one-step undo. For safety, only
`NEEDS_HUMAN_REVIEW`, `SOURCE_OWNER_REQUIRED`, and `WITHHOLD` may be applied
in bulk: `INTERNAL_REVIEW_ONLY` must always be chosen individually. Filtering
never removes original source rows from the complete CSV; native finalize still
reopens and checks the complete original source-bound packet.

After completing and finalizing an original HUMAN packet, optionally assemble
a strictly **local selected-only internal discussion copy**. This is not a
customer/client handoff or permitted disclosure:

~~~sh
python3 private-assessment-notes/selective_handoff.py \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<actual-id> \
  --position 1 --position 3 \
  --private-parent /private/operator-lightup-work
~~~

Only explicitly selected original positions currently marked
`INTERNAL_REVIEW_ONLY` are admitted. Other stages (including `WITHHOLD`)
cause a complete HOLD with no published output. The original complete HUMAN
CSV and manifest are re-admitted with unsigned exact-byte SHA binding and stage
counts before any selected output is created. A new owner-only 0700 directory
contains only the selected **masked** note bytes, scriptless selected-only
private summary HTML, a source-bound unsigned PRIVATE manifest, and a
selected-only discussion CSV. HUMAN free-text notes are withheld entirely;
no other source positions, original unmasked bytes or other HUMAN stages are
included in the selected packet.

The selected CSV is **not** a complete input for the native finalize stage.
The packet is never encrypted, recipient-authenticated, delivered or released;
its hash is not a signature. Masked text can retain secrets and personal
information. Independently verify the intended real recipient, channel,
actual consent, privacy, security and explicit HUMAN GO under the existing
original release process. This CLI intentionally exits HOLD (3) even when it
successfully wrote a private discussion copy.

The same selection is now also available through the **existing unified native
notes CLI**, without invoking an independent helper:

~~~sh
python3 private-assessment-notes/notes.py select \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<actual-id> \
  --position 1 --position 3 \
  --private-parent /private/operator-lightup-work
~~~

Both entrypoints use exactly the same native fail-closed selection function.

## Resume a browser HUMAN draft without changing original sources

The offline browser editor can now reopen its own previously exported
`PRIVATE-HUMAN-decisions-completed.csv` before invoking native `finalize`.
Choose the local file in the **Resume PRIVATE draft** control. Import is
entirely local and capped at 64 KiB: exact header, UTF-8 bytes, all original
source ordinals and unsigned original-source digests in the same order, valid
HUMAN stages, permitted small note text and the full source count must match
first. Invalid, incomplete, noncanonical, reordered or mismatched files leave
**every current browser choice untouched**. A full match still requires
explicit human confirmation before overwriting local draft selections.

Only browser-produced complete canonical CSV drafts are accepted by that UI.
The separate native `finalize` remains the authoritative source-bound
PRIVATE step. Neither reopening a draft nor an unsigned SHA authenticates
its author, establishes a grant/consent or authorizes a recipient. No browser
storage, server transmission, network, scan or background submission occurs.

## Visual original-bound selected discussion plans

The offline original PRIVATE HUMAN editor now offers a per-source
**Plan internal-only discussion** checkbox (disabled unless that particular
source has been individually marked `INTERNAL_REVIEW_ONLY`). Stage changes
back to withholding, owner-required or unreviewed status automatically
clear and disable that source's checkbox. Filtering never selects or
excludes original rows by itself.

After saving the **complete** source-bound PRIVATE HUMAN decisions CSV,
click **Save selected PRIVATE discussion plan**. Confirm the selected count:
the browser downloads `PRIVATE-HUMAN-selected-plan.json` containing only
the original source count, selected original ordinal/unsigned original-byte
SHA pairs, strict false-authority flags and HOLD. It contains **no** original
text, redacted text, HUMAN free note or recipient identity. This is an
unsigned LOCAL reference plan, not a signature, source-owner authentication,
privacy clearance or permission to share.

**Required order:** native `prepare` → browser decisions CSV and separately
browser-selected JSON plan → native `finalize` for the **whole original
source set** → native `select --plan` on the completed owner-private packet.

Store the locally downloaded plan only inside your existing private work area,
and set its owner-only file mode before native selection. Browser download
permissions are not guaranteed to be 0600:

~~~sh
chmod 600 /private/operator-lightup-work/PRIVATE-HUMAN-selected-plan.json

python3 private-assessment-notes/notes.py select \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<actual-id> \
  --plan /private/operator-lightup-work/PRIVATE-HUMAN-selected-plan.json \
  --private-parent /private/operator-lightup-work
~~~

The native command accepts **either** `--plan` **or** one or more
`--position` arguments; never both. Native admission rejects unsafe or
non-owner plans, duplicate JSON keys, extra schema keys, any implied authority,
missing/reordered/mismatched original source identities, and any planned
source that the final original HUMAN decisions did not individually mark
`INTERNAL_REVIEW_ONLY`. No selected packet is written on an admission HOLD.
Accepted plans remain source-only references; the existing fresh 0700/0600
selected internal discussion packet is created locally and the command still
returns HOLD (3). It never uploads, sends, grants permission or publishes.

If you change a HUMAN stage after exporting a plan, export a new plan after
the whole-source CSV is updated; old plans cannot override the final original
HUMAN decision. The native completed-original SHA and stage accounting remain
mandatory even when a browser selection appears valid.

### Reopening a selected-only PRIVATE plan

The offline HUMAN browser editor can **also reopen** one of its own canonical
`PRIVATE-HUMAN-selected-plan.json` files using **Reopen original PRIVATE
selected discussion plan**. If you saved complete HUMAN CSV choices separately,
restore those choices first; the plan will not set any HUMAN stage or free note.

The plan restore requires exact canonical UTF-8 JSON format, the same complete
source count and original unsigned per-position SHA identities, distinct
strictly ascending original ordinals, literal false authority flags and all
selected sources currently individually marked `INTERNAL_REVIEW_ONLY`. It
refuses modified or malformed plans atomically, without replacing any current
checkbox selections. Even a matching plan requires a separate HUMAN
confirmation. It restores only the selected UI checkboxes, not original
evidence, external approval, real recipient identity, authorization or
revocation status. This is entirely in-memory/offline; no upload or storage.
