# LightUp · PRIVATE source-bound HUMAN owner exchange

**Project status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** The new local owner exchange is an optional workflow on the existing held [PR #1647](https://github.com/Zennay/Lightup/pull/1647), **not** the original separately owned [Evidence Hub PR #1646](https://github.com/Zennay/Lightup/pull/1646) or encrypted browser [Vault PR #1640](https://github.com/Zennay/Lightup/pull/1640). These products are independent, and their file formats are **not interchangeable**. No live assets, scans, remediations, grants, review verdicts, retests, customer authentication claims, or production deployment.

## Purpose

An operator has a genuinely authorized, locally decrypted-in-memory original five-column finding source envelope (`.lue`) and its exact source-bound HUMAN coordination plan (`.lun`). Instead of transmitting *all* findings and *all* owner notes to every recipient, they can select **one pre-existing, exactly matching owner alias** and encrypt only the **original findings explicitly assigned to that alias** into a standalone `.luo` brief. The brief contains original finding ID, source-reported title/severity/retest/remediation, original record SHA-256, HUMAN coordination stage/proposed due date and that particular owner's private coordination note. It contains **no other owner's original finding or note**.

The recipient sees a clearly marked *self-declared, unverified owner* brief; they may submit an encrypted `.lur` HUMAN reply, using only non-authorizing progress states. The operator must independently verify the real actual recipient before any action. No title, status, digest, matching alias, chosen passphrase or encrypted data authenticates an actual customer, engineer or reviewer.

## Four-step private exchange

**1. Prepare one-owner encrypted brief** using original encrypted source and original encrypted plan, typed confirmation of separately authenticated actual recipient, and three interactive passphrases (source, plan, new recipient brief). No cleartext ZIP or shared-owner HTML is saved by preparation.

```sh
python -m lightup.private_export_owner_exchange prepare \
  /private/exact-source.lue /private/exact-human-plan.lun \
  --output /private/ONE-owner.luo \
  --ack-private-handling --ack-recipient-verified
```

The operator must enter an existing **exact owner alias** at the prompt. The source and plan remain unchanged. New `.luo` receives fresh scrypt/AES-256-GCM key material (fresh salt/nonce) with distinct envelope magic from other formats. The recipient passphrase must be transferred **via a separately authorized, independently verified channel**. The file is private ciphertext, not authorization or proven source identity.

**2. Recipient reads only their own brief**, optionally writes a new **unencrypted** scriptless 0600 HTML (must manually protect that output).

```sh
python -m lightup.private_export_owner_exchange read /private/ONE-owner.luo \
  --ack-private-handling

python -m lightup.private_export_owner_exchange read /private/ONE-owner.luo \
  --output /private/ONE-owner-private-brief.html \
  --ack-private-handling --ack-plaintext-html
```

**3. Recipient replies to each original finding, in the foreground**. Permitted reply labels: `no_update`, `needs_clarification`, `work_planned`, `work_in_progress`, `awaiting_evidence`, `ready_for_human_review`, `blocked`. There is deliberately **no** fixed, passed, approved, consented, retested or verified security verdict. The reply includes original record SHA for each finding and exact *encrypted brief ciphertext* SHA, and all original ID membership; it cannot be reused with a different brief (without explicit re-encryption and full human review).

```sh
python -m lightup.private_export_owner_exchange reply /private/ONE-owner.luo \
  --output /private/ONE-owner-reply.lur --ack-private-handling
```

Recipient input remains unverified HUMAN text, limited per original finding. The new `.lur` uses its own fresh AES-256-GCM authenticated envelope, format magic and passphrase; it is not encrypted with the operator source or plan key and does not modify actual LightUp records.

**4. Original operator reviews and optionally incorporates** a returned reply. Review first decrypts original `.lue` and exact `.lun`, then the actual `.luo` and `.lur`, and compares the original one-owner brief byte-for-byte to the locally reconstructed current original finding/owner subset. It refuses changed original source, changed original HUMAN plan, duplicate/orphaned finding, modified source SHA, different declared owner, or missing reply IDs. The review creates an explicitly **unencrypted** 0600 local HTML containing returned unverified progress, but does **not** change anything.

```sh
python -m lightup.private_export_owner_exchange review \
  /private/exact-source.lue /private/exact-human-plan.lun \
  /private/ONE-owner.luo /private/ONE-owner-reply.lur \
  --output /private/ONE-owner-return-review.html \
  --ack-private-handling --ack-plaintext-html
```

Once an actual human independently verifies that the reply originated from the intended person, they may opt in to a **new separately encrypted `.lun`** with nothing changed except appended `UNVERIFIED HUMAN OWNER REPLY [state]: note` text. The existing original `.lun`, source `.lue`, persisted finding/retest status, owner assignment, due date and HUMAN stage remain unchanged. Each proposed addition must fit the original bounded note size; otherwise the entire proposal is rejected **before publishing**.

```sh
python -m lightup.private_export_owner_accept \
  /private/exact-source.lue /private/exact-human-plan.lun \
  /private/ONE-owner.luo /private/ONE-owner-reply.lur \
  --output /private/NEW-human-plan.lun \
  --ack-human-reviewed-reply --ack-source-recipient-verified
```

The operator must type the complete `APPLY UNVERIFIED HUMAN NOTES` phrase in the terminal before encryption/publication. This is a HUMAN privacy friction control, not authentication or permission.

## Atomic multiple-owner reconciliation

To incorporate distinct replies from **1–32 separately verified real HUMAN recipients** in one indivisible update, specify paired encrypted `.luo` / `.lur` files. Each is independently decrypted, validated against the **unchanged original source and original plan**, and checked for duplicate alias and overlapping finding IDs. All records in all owner replies are admitted **before any new encrypted HUMAN plan is created**. Invalid or inconsistent pairs abort the entire transaction. The original source, plan and all replies remain unchanged.

```sh
python -m lightup.private_export_owner_batch \
  /private/exact-source.lue /private/exact-human-plan.lun \
  --pair /private/ALIAS-A.luo /private/ALIAS-A.lur \
  --pair /private/ALIAS-B.luo /private/ALIAS-B.lur \
  --output /private/NEW-combined-human-plan.lun \
  --ack-human-reviewed-all --ack-independent-owner-identities
```

The operator sees only the **counts** of distinct aliases, original covered records and private notes to be appended, then must type `APPLY BATCH UNVERIFIED HUMAN NOTES` before choosing a new encrypted plan passphrase. The resulting plan retains the original five-column source digest, declared client/engagement, all original finding IDs and all false-only authority assertions. It does **not** assign, repair, authorize, execute or retest an issue, and does not automatically trust owner identities.

The existing foreground operator console `python -m lightup.private_export_console` offers these workflows as options **18–23**, reusing the same underlying strict admission and no-clobber 0600 output. Original passwords and reply passwords never appear in CLI arguments.

## Privacy, authentication and release requirements

Original private exports `.lue` and HUMAN notes `.lun` are independent encrypted data. Owner briefs `.luo` and replies `.lur` are separately encrypted and passphrase-protected. A static HTML output is **NOT encrypted** even if derived from ciphertext. Local file mode 0600 does not control remote transport, backups, copied plaintext, terminal visibility or recipient behavior. Client labels, checksum matches, guessed owner aliases and acceptance prompts **are not identity verification**. Real recipients, permissions, reviewer identities and secure transfer mechanisms require human independent confirmation. Browser-exported plaintext notes are not automatically deleted.

**DRAFT/HOLD:** Source-owning [#1611](https://github.com/Zennay/Lightup/pull/1611) hosted acceptance is RED due to existing legacy unchecked-export expectations. All actual source-owner review, independent cryptography/privacy/security review, exact-head hosted and permanently named VPS CI, current *separate* authenticated client/operator consent, action-time revocation, issues #177/#182/#829 and explicit HUMAN GO remain mandatory for merging or deploying any of this. No release gates are bypassed, no old QA suites executed, no live targets or actual customer data used.
