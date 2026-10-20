# LightUp PRIVATE source-redacted HUMAN recipient replies

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Independent, new-only companion on held [PR #1681](https://github.com/Zennay/Lightup/pull/1681) pinned at 5e44510141d7e3772003934870056606bf2a84b2. Its original [PR #1673](https://github.com/Zennay/Lightup/pull/1673), original source-owner modules, scanner, grants, tenants, consent, CI and QA remain untouched.

## Complete offline workflow

The original scheduler has an encrypted selected HUMAN-only handoff action producing PRIVATE .luhq. This companion invokes the unchanged queue_handoff.decrypt and queue_handoff.admit to decrypt and fully validate that **original selected source-redacted HUMAN packet**. It does not authenticate the sender, the original source or real consent.

1. The prepare command opens the original privately encrypted .luhq using an interactive TTY passphrase, rechecks the original admission and generates a private local standalone HTML response workroom. Each originally selected HUMAN request is displayed with original request/reason, stage and tentative date. The recipient can edit local HUMAN-only status, reply and follow-up question, each bounded to 240 characters/960 UTF-8 bytes, with search plus HUMAN-stage filters and an unsaved-edits warning. A filtered bulk-stage tool previews and confirms exactly which current visible HUMAN tasks are affected and can undo its latest intact bulk edit. Bulk actions permit only neutral received/working/declined HUMAN states; they never forge a human answer, fill questions, change original source or invent verification. Individual edits invalidate bulk undo to prevent silently reverting other changes.
2. A deliberate privacy-confirmed in-browser encryption action writes a separate password-protected PRIVATE .luhr response using Web Crypto AES-256-GCM, PBKDF2-HMAC-SHA256 600,000 iterations, random salt and nonce, and purpose-separated authenticated additional data. The encrypted return contains only the SHA-256 binding to the exact selected source-redacted handoff, selected ordinal/reason pairs, and newly written HUMAN statuses/answers/questions. Original selected owner labels, tentative due dates, notes and next-action text are **not copied into the return file**. The original .luhq must be separately presented again to reconstruct the HUMAN context. Browser never calls a network API or uses browser storage. No plaintext return-file fallback on unsupported Web Crypto.
3. The open command re-admits the independently held original .luhq and decrypts the new .luhr using **two separate interactive TTY passwords**; rejects noncanonical/duplicate-key or untrusted inputs, wrong key, altered original source-redacted digest, changed selected ordinal/order or reason, malformed HUMAN entries or any positive authority flags. Only then produces a fresh PRIVATE scriptless reply summary and separate anonymous HUMAN status counts. No writeback to original source and no remediation/grant/scan.

## Operator commands

Run on the original held source tree, using its optional installed cryptography dependency. Use only separately permissioned human-only original files stored as owner-only 0600 under owner-only 0700 directories. Private output paths must be NEW absolute paths under an existing private 0700 parent.

Prepare the original selected reply form:

~~~bash
python3 remediation-human-replies/reply.py prepare \
  --handoff "$HOME/lightup-private/selected-private-human.luhq" \
  --output-dir "$HOME/lightup-private/recipient-human-reply-01"
~~~

Open recipient-human-reply-01/index.html on a trusted offline device, enter the HUMAN response, deliberately download lightup-private-human-reply.luhr with a new unique passphrase, verify that the downloaded private file actually exists and arrange separately approved private custody. Its HTML and text in browser memory can still be identifying and PRIVATE.

After receiving the original identical .luhq and the encrypted new reply from an independently approved channel:

~~~bash
python3 remediation-human-replies/reply.py open \
  --handoff "$HOME/lightup-private/selected-private-human.luhq" \
  --reply "$HOME/lightup-private/lightup-private-human-reply.luhr" \
  --output-dir "$HOME/lightup-private/human-reply-report-01"
~~~

If the recipient needs to **continue editing** an already encrypted response, preserve the original exact .luhq and saved .luhr; reopen them through the separate native resume command in a NEW private directory:

~~~bash
python3 remediation-human-replies/reply.py resume \
  --handoff "$HOME/lightup-private/selected-private-human.luhq" \
  --reply "$HOME/lightup-private/lightup-private-human-reply.luhr" \
  --output-dir "$HOME/lightup-private/human-reply-resumed-01"
~~~

Resume performs the **same** two-password original admission and exact source-redacted selected item checks as open; it generates a newly editable offline browser with previously accepted HUMAN replies, rather than silently accepting a changed original source. The new browser is plaintext PRIVATE and only its later deliberate save creates another encrypted .luhr. It does not overwrite any earlier response or output.

The new 0700 private report directory contains scriptless index.html and source-identity-free anonymous-counts.json, both 0600 via the unchanged original atomic exclusive directory publisher. Outputs never overwrite prior documents. Exit 2 = REVIEW_ONLY; exit 3 = HOLD. No positive authorization exit or claims.

## Independent PRIVATE multi-recipient HUMAN reply comparison

A separate new native reconcile.py consumes **the same exact originally selected private encrypted .luhq** and 2–8 separate locally received encrypted .luhr responses. It invokes unchanged original source-redacted selection admission once and the shared strict native response decoder for every reply, prompting separately per encrypted return. Every reply must match the exact redacted source digest, complete original selected ordinal/reason membership and valid HUMAN-only response shape. An identical encrypted reply file cannot be counted twice.

It publishes only after **all** returned files and the original redacted handoff are admitted and rechecked against the same source bytes. A NEW private 0700 output contains scriptless side-by-side review grouped by selected original ordinal, an anonymous counts-only JSON and PRIVATE handling instructions, all 0600. Reviewers see literal differences between local file slots in claimed HUMAN stages, replies and questions. This is not automatic remediation or evidence; a matching answer may be from the same person twice. The tool does not assert number of independent humans, identity, chronology, signed claims, verified findings or actual consent. Free-form HUMAN responses and original action text are PRIVATE; the anonymous summary may identify small cohorts.

    python3 remediation-human-replies/reconcile.py \
      --handoff "$HOME/lightup-private/selected-private-human.luhq" \
      --reply "$HOME/lightup-private/selected-reply-A.luhr" \
      --reply "$HOME/lightup-private/selected-reply-B.luhr" \
      --output-dir "$HOME/lightup-private/private-human-comparison-01"

Repeat --reply for 2–8 different locally received encrypted response files. It rejects duplicate file paths, identical ciphertext packages, missing or changed original, malformed passwords or any replied claim of authority without partial publication. Exit 2=REVIEW_ONLY; 3=HOLD. There is no automatic selection of a winning opinion or assertion of consensus.

## Portable complete software-only distribution and strict receiving

The independent new distribution.py composes the original held pinned native evidence-remediation suite, the unchanged source-free scheduler, and all new recipient reply sources into one complete offline runnable software-only tree. No evidence, client files, private notes or passwords are packaged. No original/source-owner files or active branches are edited. The original native bundle.build, bundle.inspect and bundle_receive.admission are reused unchanged for independent exact native source admission.

Build under an already existing owner-only private 0700 parent, with the complete original held source tree available:

    python3 remediation-human-replies/distribution.py build --output-dir "$HOME/lightup-private/software-human-replies-01"

The new PRIVATE software portal is software-human-replies-01/software/index.html. The private build also contains the deterministic full software ZIP, its manifest, the unchanged original scheduler software ZIP and its separate original manifest. All are *unsigned* byte receipts, not sender authentication or permission. The original software-only assets and original-home.html remain unchanged within the new portable runnable tree; only the newly generated root landing page is replaced by a reply-aware portal.

A recipient with separately trusted matching source code and the four separately acquired 0600 files can strictly unpack to a NEW 0700 directory:

    python3 remediation-human-replies/distribution.py receive \
      --archive "$HOME/lightup-private/software-human-replies-01/LightUp-PRIVATE-HUMAN-Reply-Software-DRAFT-HOLD.zip" \
      --manifest "$HOME/lightup-private/software-human-replies-01/bundle-manifest.json" \
      --parent-archive "$HOME/lightup-private/software-human-replies-01/original-scheduler-software-only.zip" \
      --parent-manifest "$HOME/lightup-private/software-human-replies-01/original-scheduler-manifest.json" \
      --output-dir "$HOME/lightup-private/software-received-01"

The receiver applies unchanged original native source/asset admission, checks all original scheduler files byte-for-byte against independently held trusted source code, checks all five additive reply files and its generated portal, requires exact complete ZIP inventory/modes/digests/bounds, rechecks the four original received files immediately before atomic non-overwriting publication and never invents actual sender identity or human consent. Open software-received-01/index.html offline.

The optional distribution.py inspect --workspace ABSOLUTE_PATH operation is for a *complete locally built* distribution directory, not the smaller received runnable subset. All operations exit 2=REVIEW_ONLY or 3=HOLD, never grant security authority. Syntax/manifest checks are not client authorization, independent security/crypto review, actual owner acceptance or real release.

## Security and limitations

Original .luhq already excludes case identifiers, original evidence, target, original source packet digests and original counts. Its selected HUMAN planning text may still be identifying. The smaller .luhr return deliberately does not repeat original owner names, original actions or original selected private notes; it contains only the original digest, ordinal/reason and recipient HUMAN replies/questions. This deliberate redaction makes it **impossible** to correlate this return to real verified original case identities; this workflow binds only to the exact originally selected redacted HUMAN task payload. Free text can still contain identifying information. Browser HTML, printable report, and small-cohort anonymous counts remain PRIVATE; no auto-send, auto-sharing or secure erase.

A valid hash/password/AEAD tag only protects local file integrity/confidentiality, **not** an authenticated sender, scope, client/operator consent, current revocation status, valid finding, retest, resolved issue, remediation authorization or HUMAN GO. HUMAN replied does not mean fixed; missing entries never mean fixed. No live target, network request, model, scan, native Apply, grant, release or original source modification.

**External gates remain DRAFT/HOLD:** exact-head hosted GitHub plus permanent named VPS CI, original source-owner plus independent security/privacy/browser/crypto review, unresolved #177/#182/#829, genuinely current independent authenticated client + operator consent including revocation at action-time, and explicit HUMAN GO. Do not merge to main or deploy without those approvals. No new QA/regression/testsuites were made or requested. A syntactic build is not an end-to-end browser security approval.
