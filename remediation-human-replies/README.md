# LightUp PRIVATE source-redacted HUMAN recipient replies

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Independent, new-only companion on held [PR #1681](https://github.com/Zennay/Lightup/pull/1681) pinned at 5e44510141d7e3772003934870056606bf2a84b2. Its original [PR #1673](https://github.com/Zennay/Lightup/pull/1673), original source-owner modules, scanner, grants, tenants, consent, CI and QA remain untouched.

## Complete offline workflow

The original scheduler has an encrypted selected HUMAN-only handoff action producing PRIVATE .luhq. This companion invokes the unchanged queue_handoff.decrypt and queue_handoff.admit to decrypt and fully validate that **original selected source-redacted HUMAN packet**. It does not authenticate the sender, the original source or real consent.

1. The prepare command opens the original privately encrypted .luhq using an interactive TTY passphrase, rechecks the original admission and generates a private local standalone HTML response workroom. Each originally selected HUMAN request is displayed with original request/reason, stage and tentative date. The recipient can edit local HUMAN-only status, reply and follow-up question, each bounded to 240 characters/960 UTF-8 bytes, with local filters and an unsaved-edits warning.
2. A deliberate privacy-confirmed in-browser encryption action writes a separate password-protected PRIVATE .luhr response using Web Crypto AES-256-GCM, PBKDF2-HMAC-SHA256 600,000 iterations, random salt and nonce, and purpose-separated authenticated additional data. Original selected task membership and the SHA-256 of the exact source-redacted original contents remain inside the encrypted return. Browser never calls a network API or uses browser storage. No plaintext return-file fallback on unsupported Web Crypto.
3. The open command re-admits the independently held original .luhq and decrypts the new .luhr using **two separate interactive TTY passwords**; rejects noncanonical/duplicate-key or untrusted inputs, wrong key, altered original selected task payload, changed ordinal/order, altered reason, malformed HUMAN entries or any positive authority flags. Only then produces a fresh PRIVATE scriptless reply summary and separate anonymous HUMAN status counts. No writeback to original source and no remediation/grant/scan.

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

## Security and limitations

Original .luhq already excludes case identifiers, original evidence, target, original source packet digests and original counts. This deliberate redaction makes it **impossible** to correlate this return to real verified original case identities; this workflow binds only to the exact originally selected redacted HUMAN task payload. Free text can still contain identifying information. Browser HTML, printable report, and small-cohort anonymous counts remain PRIVATE; no auto-send, auto-sharing or secure erase.

A valid hash/password/AEAD tag only protects local file integrity/confidentiality, **not** an authenticated sender, scope, client/operator consent, current revocation status, valid finding, retest, resolved issue, remediation authorization or HUMAN GO. HUMAN replied does not mean fixed; missing entries never mean fixed. No live target, network request, model, scan, native Apply, grant, release or original source modification.

**External gates remain DRAFT/HOLD:** exact-head hosted GitHub plus permanent named VPS CI, original source-owner plus independent security/privacy/browser/crypto review, unresolved #177/#182/#829, genuinely current independent authenticated client + operator consent including revocation at action-time, and explicit HUMAN GO. Do not merge to main or deploy without those approvals. No new QA/regression/testsuites were made or requested. A syntactic build is not an end-to-end browser security approval.
