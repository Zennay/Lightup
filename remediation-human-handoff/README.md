# LightUp — PRIVATE HUMAN action handoff (DRAFT/HOLD)

This standalone, **offline** companion turns **an existing exact-matched saved anonymous numeric browser session and local HUMAN routing board** from the unchanged [remediation-portfolio](../remediation-portfolio/README.md) into *separate, human-readable follow-up packets grouped by selected HUMAN next action*.

It solves a practical operator gap: routing choices in a combined private board are not yet individual, reviewable, least-disclosure human handoffs. A human can now prepare just the follow-up needed for a manually chosen original authorized reviewer instead of sharing an entire local numerical dashboard. This feature **does not send anything**, grant authority or update the original source.

## Private encrypted offline HUMAN work-session save / resume

The portable `browser.html` now offers a **single password-encrypted backup** of its complete source-free HUMAN operating state (strict original numeric session, paired original board, edited local board and optional peer proposal). It avoids putting *that particular new resumable backup* on disk in readable JSON. **No original case identity, security proof, consent or authorization is added.**

- Browser-native WebCrypto PBKDF2-HMAC-SHA-256, **600,000 iterations** and a fresh 16-byte cryptographically random salt derives a non-exportable AES-256-GCM key; 12-byte fresh random nonce, 128-bit integrity tag and a pinned application-domain associated-data value bind ciphertext to this format.
- **Exactly versioned `.lhew` envelope** (schema/kdf/iteration/salt/nonce/ciphertext) with no plaintext numerical metadata. Restore checks bounded UTF-8, recursively rejects duplicate JSON keys, enforces canonical base64 and exact accepted envelope fields/algorithms, verifies AEAD integrity and then *re-admits the entire original native source-free numeric session, original HUMAN board, current edited board and any peer board* before replacing browser state.
- Password length **14–256 characters** (NFC canonical, no outer whitespace), with a second confirmation on save. Secret input fields are emptied immediately upon button activation. The app keeps no key in localStorage, sessionStorage, IndexedDB, cookies or cloud services. Wrong passwords, malformed/tampered files and canceling a replacement keep the previous valid browser state.
- Encrypted save is **only available where WebCrypto is exposed in a secure browser context** (typically supported local `file://` contexts, depending on browser). If unsupported, the control remains unavailable; there is no plaintext fallback.
- **Critical scope:** the new encrypted `.lhew` backup protects *only that new backup*. The original Studio numeric session, prior board and standard HUMAN reports remain plaintext and may still be privacy-sensitive. Neither encryption nor CSP substitutes independent security review, source identity, secure device management or consent. Forgotten passphrases cannot be recovered. A weak or reused passphrase can still be guessed offline.

To use: load the original strict numeric session and matching board as described below, make HUMAN-only edits, enter a strong unique passphrase and confirm it in section 5, then download the encrypted file. To resume, select the `.lhew` file and enter the same passphrase; if the current session has local choices, explicitly confirm replacement *after* all validation succeeds. The offline editor restores your original/local/peer HUMAN routing proposals, not original source authority.

## Encrypted least-disclosure HUMAN handoff capsule

The offline browser now also encrypts **only the selected source-free HUMAN handoff**, without wrapping the complete internal workroom or original numeric session. In the source-free Studio, choose a HUMAN action plus optional *one local ordinal* in section 3, then enter a separate strong passphrase in section 6 and click **Encrypt selected HUMAN action only**. The produced `.lheh` file contains one strictly bounded source-free payload with only the selected ordinal(s), numerical slot/question appearances, action, unverified local state and all 12 literal false authority flags **inside** ciphertext. The clear envelope only identifies the encryption format and KDF parameters.

A recipient can open `browser.html` locally, choose the encrypted handoff in section 6, and decrypt into a **read-only HUMAN table** without any original numeric session, full private workroom or account credentials. No original case ID, verified security finding, authentic approval, client consent, action authority or authenticated sender is inferred. A wrong password, tampered file, unexpected fields, duplicated JSON key, mismatched cryptographic purpose or malformed selected rows HOLD; a failed open clears the previous displayed recipient handoff.

The envelope is explicitly **separate** from the full `.lhew` work-session backup: `.lheh` has its own fixed AEAD associated-data domain, kind, encrypted schema and strict row limits, so neither can be substituted for the other. PBKDF2-HMAC-SHA-256 (600,000 iterations, independent 16-byte salt) and AES-256-GCM (independent 12-byte nonce) protect confidentiality and tamper detection *only to the extent that the recipient keeps the password secret and their device/browser are trustworthy*. There is no identity signature, recovery service, recipient authentication or proof of actual delivery. Never send the password in the same message as the file. Encrypted files are still subject to the project's original HUMAN disclosure authorization and privacy requirements.

## Explicit clearing of displayed PRIVATE HUMAN data

Section 7 of the offline Return Studio now provides a **Clear all loaded local HUMAN data** action. After a confirm prompt, the browser drops in-memory references to the admitted numeric session, original/edited/peer boards, clears the currently unlocked encrypted HUMAN handoff table, the selected original/peer/encrypted file inputs, local selection filters and all save/unlock passphrase fields. Changing the original files and restoring a separate encrypted session also clears any formerly decrypted handoff view. This reduces the chance of the next local operator seeing the last person's HUMAN numbers.

**Important limits:** clearing references does not securely overwrite garbage-collected browser process memory, OS swap, clipboard contents, previously downloaded plaintext files, existing encrypted backups or anything outside this page. Closing the browser and applying device/disk protections remain the user's responsibility. No claim of secure memory erasure.

## No-Python: portable offline HUMAN Return Studio

Open **[browser.html](browser.html)** directly on an offline computer. It is a self-contained HTML file with an embedded SHA-256 CSP-pinned local script, no third-party resources and no server or installation.

1. In the **unchanged original** `remediation-portfolio/studio.html`, download the paired saved PRIVATE numeric session JSON and local HUMAN action-board JSON.
2. In the new Return Studio choose those **two** files and click **Load both PRIVATE files**. The entire selection is admitted together or HOLD: bounded UTF-8, complete original exact schemas, recursive duplicate JSON-key rejection, literal false authority flags and positional equality across **all** local numeric packets.
3. Change HUMAN-only routing action/state from the accessible per-ordinal table; do not infer case identity or a verified fix.
4. Download an **original Studio-compatible board** with the new HUMAN choices. It can be restored manually in the original Studio **only against the same numeric session**; the native Python CLI can also read it without alteration.
5. Restrict the HUMAN handoff to one action category or all actionable local appearances, then download its standalone *scriptless* print-friendly HTML, CSV or text brief. The browser also exports source-free aggregate planning JSON and an action/state change CSV.

All original input is read only into transient browser memory: no fetch, IndexedDB, localStorage, cookies, analytics, network, external images, model, background worker or target access. Downloads are **not** encrypted at rest and anonymous small-group numbers can be sensitive. A HUMAN must decide when to disclose anything. The new standalone browser does **not** show original evidence or authenticate actual original human replies.

For auditability of the deliverable's SHA-pinned script and to reproduce the distributable HTML using the checked-in source (not a QA suite):

```bash
python3 remediation-human-handoff/build_browser.py
```

The resulting `browser.html` is a static private offline product, **not** an independent browser/security audit or permission to release. Existing release HOLD is unchanged.

### Comparing two LOCAL HUMAN routing proposals in the browser

The standalone Studio now includes a second, explicitly imported `peerFile` board selector. A second HUMAN reviewer may submit their local source-free routing draft **for the identical current numeric packet selection**; this does not prove real reviewer identity or cases. All pair fields, exact enum codes and 12 literal false flags are independently admitted before any peer difference appears. For every locally different anonymous ordinal, the operator sees original local action/state, peer-proposed action/state, and their current draft; **each** adoption requires its own explicit HUMAN confirmation. Changes are never automatically merged or sent.

The `peerCsv` export contains only the numeric ordinal and these local action/state enum differences, no original client/evidence/target identity or dates. A change of file clears prior peer candidates. Switching the original numeric session clears the entire browser state (including peer), and failed peer admission leaves the current HUMAN draft untouched. Download the ordinary native v1 board after manually deciding which suggestions to retain; the unchanged original Studio still independently re-admits it.


## Use (offline Linux, stdlib Python)

Open the original `remediation-portfolio/studio.html` in an offline browser. Import the original native anonymized counts-only exports, save the numeric private session, make HUMAN-only next-action choices and export the matching action board. Save **both** downloads inside one folder owned by the same local account, with mode 0700 for the parent and 0600 for both files.

```bash
mkdir -m 700 -p "$HOME/lightup-private-human"
install -m 600 ~/Downloads/PRIVATE_SESSION.json "$HOME/lightup-private-human/session.json"
install -m 600 ~/Downloads/PRIVATE_BOARD.json "$HOME/lightup-private-human/board.json"

python3 remediation-human-handoff/handoff.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --output-dir "$HOME/lightup-private-human/all-actions"

# Least-disclosure packet for one HUMAN action:
python3 remediation-human-handoff/handoff.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --only request_original_human_review \
  --output-dir "$HOME/lightup-private-human/original-owner-review"

# Disclose only one human-selected ordinal in one exact action group:
python3 remediation-human-handoff/handoff.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --only request_original_human_review \
  --ordinal 1 \
  --output-dir "$HOME/lightup-private-human/one-local-row"
```

Open `all-actions/index.html` **locally**; follow the action-group links. Each non-empty selected group has matching `handoff-ACTION.html`, `.csv`, and `.txt`. The source-free `handoff-summary.json` records the exact requested action scope, action/state appearances and literal false authority flags. Empty groups receive no handoff files. No-action choices are excluded, **never silently considered resolved**. An explicit `--only` hides other groups but does not assert that missing groups are zero. `--ordinal N` requires a matching `--only ACTION`, validates that the exact selected row actually has that action, and publishes just that one locally declared ordinal. This is not a client/case identifier. Filtered exports omit unselected original packet counts rather than disclosing them. The browser reports are print-friendly, keyboard-link navigable and scriptless with network-blocking CSP.

## Offline HUMAN status return to original Studio

The original Studio allows importing a local source-free HUMAN routing board, but an operator who receives an action packet could not apply an individual local state change through the CLI without manually reconstructing the entire board. The independent `return_to_studio.py` closes this loop **without touching original evidence**.

```bash
python3 remediation-human-handoff/return_to_studio.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --ordinal 1 \
  --expect-action request_original_human_review \
  --new-state waiting_original_owner \
  --output-dir "$HOME/lightup-private-human/local-return-01"
```

A fresh private 0700 folder contains `board.json` (native Studio-compatible v1), `change-summary.json` (one self-declared local state transition; 12 authority flags all false), and scriptless `index.html`. Each file is 0600. It requires the **exact current session** and the full matching prior board, refuses unknown ordinals/actions, rejects a no-op state transition, and strictly re-admits the produced board through the original owner parser before exclusive publication. The prior board remains unchanged. In the **same offline Studio session**, restore the new `board.json` manually; Studio itself independently checks all packet ordinals and numeric shapes.

The local return does not prove that an authentic original HUMAN reviewer replied. In particular, `locally_discussed` is **never** a verified fix or original-source decision; no native evidence or ticket workflow is modified. A new file is not a delivery receipt or consent.

## Multiple HUMAN status changes in one atomic return

Create the PRIVATE complete human-editable update worksheet **without hand-writing any schema fields**:

```bash
python3 remediation-human-handoff/prepare_updates.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --output-dir "$HOME/lightup-private-human/change-worksheet"
```

The new owner-only directory contains 0600 `updates.json` plus `HOW_TO_EDIT.txt`. Every local packet is prefilled with the exact source-free ordinal, current HUMAN action/state and all 12 false authority flags. `new_state` is deliberately **identical to the original state**, so the template cannot accidentally change any status. In a local private editor, remove all unwanted change rows and explicitly change `new_state` in the remaining rows. Apply the edited 0600 file with the CLI below. The filename and fields are HUMAN-only, not source identity.

For a full 1–12-row human-only offline return, `bulk_return.py` reads an explicitly authored PRIVATE 0600 strict manifest of local proposed transitions. The manifest must contain **exactly** these top-level fields: `kind`, `schema_version`, `disposition`, `changes`, `warning` and the 12 original literal false authority flags. Values for the first five:

```json
{
  "kind": "lightup.private_local_human_routing_changes",
  "schema_version": 1,
  "disposition": "HUMAN_ONLY_UNVERIFIED_LOCAL_ROUTING_PROPOSALS",
  "changes": [
    {
      "ordinal": 1,
      "expect_action": "request_original_human_review",
      "expect_state": "needs_human_followup",
      "new_state": "waiting_original_owner"
    }
  ],
  "warning": "Self-declared proposed LOCAL HUMAN routing states only. Not an authentic reviewer reply, source observation, authorization, remediation, retest, client consent, finding, grant, scan or release."
}
```

The remaining **12 false authority fields** are required exactly, and can be copied from the *already provided original Studio v1* action-board export only after locally checking they are all literal JSON `false`. Do not replace authentic source records with this manifest.

```bash
python3 remediation-human-handoff/bulk_return.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --changes "$HOME/lightup-private-human/updates.json" \
  --output-dir "$HOME/lightup-private-human/batch-return-01"
```

Every selected ordinal must be distinct, within the original numeric session and match **both** the expected old action and expected old state. Empty, duplicate, no-op, malformed, unauthorized or inconsistent batches fully HOLD. It then creates one new private scriptless HUMAN review page, structured local change summary and a native v1 `board.json` which the original parser must re-admit against the unchanged entire numeric session before the atomic publication. This **never** asserts verified remediation or sends a reply. All inputs are separately private and must be shared by a HUMAN only after an appropriate disclosure decision.

## Offline local HUMAN before/after desk (not verified progress)

After returning a native board, a HUMAN can inspect **only the local routing differences** between the earlier and later source-free boards bound to the SAME exact numeric browser session:

```bash
python3 remediation-human-handoff/compare_returns.py \
  --session "$HOME/lightup-private-human/session.json" \
  --earlier-board "$HOME/lightup-private-human/board.json" \
  --later-board "$HOME/lightup-private-human/batch-return-01/board.json" \
  --output-dir "$HOME/lightup-private-human/local-routing-diff-01"
```

The result is a fresh private 0700 folder with scriptless `index.html`, local ordinals and action/state differences in `changes.csv`, and counts-only `changes.json`, all 0600. The original parser independently validates each board and all local ordinals against the SAME current PRIVATE session; no locally changed action/state means HOLD rather than claiming positive progress. No original clients, sources, case IDs, case continuity, timestamps, verified fixes or consent are inferred. Multiple numeric ordinal appearances are **not** unique records.

## One-command PRIVATE HUMAN workflow (complete atomic workroom)

The existing individual CLI products are now **physically integrated**, without modifying any source-owner files, by [`workflow.py`](workflow.py): it performs one complete offline edit-to-return-to-handoff cycle using the strict original local source-free numeric session and the unchanged current local HUMAN board.

```bash
python3 remediation-human-handoff/workflow.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --changes "$HOME/lightup-private-human/change-worksheet/updates.json" \
  --output-dir "$HOME/lightup-private-human/complete-workroom"

# Optional least-disclosure action group:
python3 remediation-human-handoff/workflow.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --changes "$HOME/lightup-private-human/change-worksheet/updates.json" \
  --only request_original_human_review \
  --output-dir "$HOME/lightup-private-human/limited-workroom"
```

The private `index.html` links to three independently source-bound modules, all inside the same *fresh, owner-only* 0700 directory: `return/` (native Studio-v1 `board.json` plus scriptless change brief), `handoff/` (HTML/CSV/TXT local HUMAN follow-up actions) and `difference/` (earlier/later local action/state difference desk). A separate `summary.json` documents source-free counts and all 12 literally false original authority flags. Output file modes are 0600; subfolders 0700. Each existing original local validation boundary remains intact and the new native board is re-admitted before any publication. Crucially, these subfolders are built inside one **unpublished private staging directory**; if any phase fails, the entire stage is discarded and the requested final folder never appears. Final publication uses the existing Linux exclusive no-replace rename.

The human-written change worksheet must have at least one real local proposal change; a default no-op worksheet cannot produce a fictional progression. This is a portable operator workroom, not an actual client remediation pipeline, delivered correspondence or approval. A HUMAN must still manually restore the native JSON in the original offline Studio and separately consult authentic original evidence and current permissions.

## Direct browser-export → complete PRIVATE CLI workroom (no edit manifest)

The browser can edit both HUMAN action and state. Operators can now download the resulting original-native v1 routing board and feed it **directly** to [`browser_workflow.py`](browser_workflow.py), without manually preparing a JSON `changes` manifest:

```bash
python3 remediation-human-handoff/browser_workflow.py \
  --session "$HOME/lightup-private-human/session.json" \
  --original-board "$HOME/lightup-private-human/board.json" \
  --proposed-board "$HOME/lightup-private-human/browser-return.json" \
  --output-dir "$HOME/lightup-private-human/browser-workroom-01"

# Optional: only hand off locally proposed original HUMAN review actions
python3 remediation-human-handoff/browser_workflow.py \
  --session "$HOME/lightup-private-human/session.json" \
  --original-board "$HOME/lightup-private-human/board.json" \
  --proposed-board "$HOME/lightup-private-human/browser-return.json" \
  --only request_original_human_review \
  --output-dir "$HOME/lightup-private-human/browser-workroom-02"
```

Use `install -m 600` to place both browser-downloaded board files into the same owner-private 0700 directory as the session. **Both** independently pass the original source-free native Studio session+board parser. A no-op edited board is HOLD; actual action/state changes are counted by ordinal only (not identity or chronology), and do **not** require identical actions across before/after. It builds one private, exclusively published workroom containing `return/board.json` (fully source-bound native v1 format), `handoff/` (action-selected HUMAN follow-ups), `difference/` (all anonymous local routing differences), root navigable scriptless `index.html`, and counts-only `summary.json`. Each stage is private 0700; files 0600. A downstream failure discards the entire staging workroom without publishing partial output.

This route does NOT turn a browser download into authenticated evidence, identify a human reviewer, prove a real client case, accept consent, perform a fix or grant target access. The original source records never change. Full release HOLD remains as below.

## Restrict an individual HUMAN handoff to exactly one local ordinal

The browser HUMAN handoff panel now has two independent controls: selected next-action category and **one exact local anonymous ordinal** (or all). The HTML, CSV and TXT handoff downloads include only the selected actionable row(s); other packet rows are not included. The native Studio return and the separate counts-only planning summary still contain their own entire numeric session context; **do not distribute those** when only a limited HUMAN handoff was approved.

Both one-command CLI workrooms also accept `--only ACTION --ordinal N`. This passes the original strictly admitted session/board through the existing `handoff.py` exact action+ordinal selector, so `handoff/` contains only the chosen local packet appearance. A mismatching action, nonexistent ordinal or unpaired `--ordinal` makes the whole new workroom HOLD.

```bash
python3 remediation-human-handoff/browser_workflow.py \
  --session "$HOME/lightup-private-human/session.json" \
  --original-board "$HOME/lightup-private-human/board.json" \
  --proposed-board "$HOME/lightup-private-human/browser-return.json" \
  --only request_original_human_review --ordinal 1 \
  --output-dir "$HOME/lightup-private-human/limited-private-workroom"
```

**Critical privacy distinction:** `--ordinal` filters **only the outbound `handoff/` artifacts**, not the internal complete native `return/` board, original-session-derived workroom-wide summary, or `difference/` report. The complete workroom remains PRIVATE operator material, *not* a minimum-disclosure transfer package. If authorized to disclose one anonymized HUMAN follow-up, share **only** the selected `handoff/handoff-ACTION.html` (or its CSV/TXT), not the whole workroom or the original saved session. Ordinal is never a real case identifier.

## Hard boundaries

- The existing owner-controlled `remediation-portfolio/action_board.py` is the **sole** import contract: original producer format, bounded/private no-follow file admission, duplicate-key rejection, **exact** numeric packet shape and ordinal matching, all literal false authority flags. A mismatching board or input rejects the whole operation before any final publication. We do not rewrite, fork or relax the original parser.
- Output appears only in a **fresh** folder under an existing owner-only 0700 parent; the staging directory is private and only 0600 files are written. Publication is exclusive Linux `renameat2(RENAME_NOREPLACE)`, with fsync; existing destinations remain untouched.
- Nothing is sent, imported to other systems, uploaded, cached in browser storage, mapped to a real client/finding, scheduled, scanned or marked remediated. The local packet ordinal is **not** an original case ID. Sort is purely HUMAN waiting/follow-up state and local question volume, never risk severity or authentic prioritization.
- Private numeric exports may still disclose sensitive small-cell information and **are not encrypted at rest**. An actual human must decide disclosure and independently authenticate current original records and both parties' authority through the genuine source workflow.
- LightUp remains **INCUBATE · M3/M7 PLAN-LAB ONLY · DRAFT/HOLD**. Original source-owner and independent security/privacy review, original hosted plus permanent named VPS exact-head CI, #177/#182/#829, separate authentic client/operator consent with action-time revocation and explicit HUMAN GO remain required before any main merge, real-client operation or deployment. This local companion itself supplies none of those approvals.

## Isolation

Only new `remediation-human-handoff/` files. Built on pinned existing independent `remediation-portfolio/` companion; does not mutate original owner branch, source evidence, QA/tests, auth/scan/grant paths, CI or deployment. If original native source format evolves, update via a separate owner-reviewed source contract rather than guessing.
