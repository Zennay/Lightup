# LightUp · signed PRIVATE original HUMAN reply courier

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Independent, new-only
companion to held original source-redacted HUMAN reply PR #1684,
pinned at original commit 1ce2e3450c73e1bc68399b6690202d2bedc8ddf6.
The original has source-bound private encrypted HUMAN responses, but AES-GCM
alone does not prove who authored a response. This adds an independent offline
Ed25519 signature binding the original encrypted handoff and reply bytes.
No original application, scope, grant, scanner, model, CI or test files changed.

## New encrypted signing key

Under a NEW owner-private 0700 directory with approved local custody:

    python3 remediation-human-signed-courier/signed_courier.py keygen \
      --directory /ABSOLUTE/PRIVATE/new-signer-keys

Creates owner-only 0600 PEM files with password-protected private signing key.
Never transfer this private key. Separately confirm the resulting SHA-256
DER/SPKI public-key fingerprint with the recipient via an independently
trusted channel. An untrusted transfer cannot establish its own trust.

## Seal an already-original-validated HUMAN reply

First use the unchanged original human-replies app to create the exact
source-redacted encrypted selected handoff (.luhq) and recipient response
(.luhr). Do not include plaintext client evidence or private notes in this
new courier. From a private interactive terminal:

    python3 remediation-human-signed-courier/signed_courier.py seal \
      --handoff /ABSOLUTE/PRIVATE/selected-original.luhq \
      --reply /ABSOLUTE/PRIVATE/original-answer.luhr \
      --signing-key /ABSOLUTE/PRIVATE/new-signer-keys/signing-private.pem \
      --output /ABSOLUTE/PRIVATE/first-answer.luhs

The original unchanged reply.source and reply.admitted_reply require
the two original passwords and prove exact selected original source binding,
all original HUMAN ordinal/reason rows and no-authority claims before any
digital signature is produced. A separate signing-key password is requested.
The canonical bounded .luhs contains only the two encrypted original byte
images, their SHA-256 digests, zero-authority flags and a domain-separated
Ed25519 signature. No decrypted HUMAN return is stored in this courier.

## Recipient: inspect signature without decrypting private text

    python3 remediation-human-signed-courier/signed_courier.py inspect-signature \
      --courier /ABSOLUTE/PRIVATE/first-answer.luhs \
      --trusted-fingerprint 64-lowercase-hex-from-separate-trusted-channel

This checks encrypted byte custody against a public key confirmed independently
out of band. It does NOT prove that the original source/reply decrypt and
admission succeeded; nor does it authenticate a real person or client.

## Recipient: re-admit using the ORIGINAL native HUMAN source

    python3 remediation-human-signed-courier/signed_courier.py receive \
      --courier /ABSOLUTE/PRIVATE/first-answer.luhs \
      --trusted-fingerprint 64-lowercase-hex-from-separate-trusted-channel \
      --output-dir /ABSOLUTE/PRIVATE/received-first-answer

The receiver verifies the exact Ed25519 signature, strict canonical ciphertext
byte manifest, independently trusted key fingerprint, and then invokes the
unchanged original reply.open_reply for the two private password prompts.
Only after all original admission succeeds is a new 0700/0600 PRIVATE
workroom atomically published without replacing existing files. Its scriptless
index.html opens the unchanged original native HUMAN response report.
Add --resume to invoke the original editable HUMAN continuation instead.

## Original-source 2–8 signed HUMAN reply inbox

Receive multiple separately provided encrypted HUMAN couriers, each with its
own independently trusted public fingerprint and all bound to EXACT SAME
original selected encrypted .luhq. Original native reconcile.compare performs
every original source and individual response membership admission after
signature verification; the new owner-private result is published atomically.

    python3 remediation-human-signed-courier/signed_inbox.py \
      --signed-courier /ABSOLUTE/PRIVATE/first-answer.luhs \
      --trusted-fingerprint FIRST-EXTERNALLY-CONFIRMED-64-HEX \
      --signed-courier /ABSOLUTE/PRIVATE/second-answer.luhs \
      --trusted-fingerprint SECOND-EXTERNALLY-CONFIRMED-64-HEX \
      --output-dir /ABSOLUTE/PRIVATE/fresh-signed-human-inbox

A complete new private scriptless inbox links to the original native response
comparison and records exact source/reply encrypted-byte fingerprints. Different
signatures, public keys, ciphertext or file slots do NOT prove different people
or independent reviewers. Duplicate ciphertext, source mismatch, invalid
signature or original source admission means HOLD and no partial inbox output.

## Explicit privacy and release boundaries

- All private inputs must be absolute, regular, owner-only 0600,
  single-link files under owner-only 0700 directories. Files are bounded.
  Output paths are new and never overwritten. Success exits 2 REVIEW_ONLY;
  failure exits 3 HOLD. No network, scanner or live target interaction.
- Signing keys are passphrase-protected; passwords are interactive only.
  A transferred public key is NOT automatically trusted: confirm the public
  fingerprint independently using a trustworthy separate channel.
- Digital signatures prove possession of a particular private key over exact
  encrypted bytes, not actual human identity, client/operator consent,
  truth of a reply, original evidence authenticity, fix, retest, grant,
  scanner/execution authority, approval, deployment or HUMAN GO.
- Private HUMAN responses can contain confidential or identifying text;
  the original native decrypted HTML and JSON output remain PRIVATE.
  The courier remains sensitive even though its HUMAN contents are encrypted.
- These tools do not provide PKI, automatic key revocation, human independence,
  client authorization, release gates or an automatic winning answer.
- Notion stage INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD remains. Original
  exact-head hosted and named permanent VPS CI, original owner and
  independent security/privacy/crypto/browser review, issues #177/#182/#829,
  separate current authenticated client/operator consent and action-time
  revocation, explicit HUMAN GO required before any main merge/deployment.

Dependencies: Python 3.11+, cryptography from independently approved local
installation and the existing unchanged source folders
remediation-human-replies, remediation-recipient-scheduler, and
remediation-integrated-workspace from the pinned held source branch.
This new independent product creates and runs no QA/regression/test suites.
