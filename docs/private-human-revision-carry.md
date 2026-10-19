# LightUp · encrypted HUMAN source revision carry (PRIVATE / DRAFT-HOLD)

This is a **real offline HUMAN workplan continuity feature** for a new original authenticated encrypted export. It is an optional add-only child of the original PRIVATE source/export owner [PR #1647](https://github.com/Zennay/Lightup/pull/1647), pinned to original parent SHA `10785c55135271809182edbf03c33d524c1813f2`. No parent modules are changed; the separate source-owner PR and its release gates are respected. Requires the parent optional Python `cryptography` dependency.

## Why it exists

The original source-backed `.lue` finding export contains **five columns only**: original finding ID, title, severity, source-claimed retest status, and remediation. A separate encrypted `.lun` workplan contains local HUMAN planning only (stage, alias, proposed date, note), and is bound to the **exact original CSV digest**. When a later original encrypted `.lue` export arrives, directly reusing the old `.lun` is correctly rejected. The new bridge rebuilds an entirely new `.lun` bound to the new source while carrying only eligible human notes; it never overwrites the earlier source or plan.

### Conservative carry policy

- Fully decrypt and authenticate each separate `.lue` source independently in RAM using the original `_read_encrypted`/guarded manifest and canonical CSV parser. Strictly decrypt and validate the **complete old** `.lun` against the old original source using `_read_plan`; no partial input admitted.
- Require separate operator acknowledgment that the two inputs really concern the **same authentic client and engagement**, beyond self-declared matching IDs. Reject conflicting labels even with human acknowledgment.
- Compare original records using **all five exact original exported columns**, not just a finding ID, severity or digest. Added or changed records start with entirely blank HUMAN planning. Absent records are not migrated or called fixed. No carried notes for modified original text, status, or severity.
- Default `carry`: only **HUMAN owner alias and HUMAN private note** for exact five-column matches. Stages and proposed dates restart at **unassigned / blank**, even for an identical row. Independent optional `--carry-stage --ack-human-stage-carryover` carries HUMAN stage/date on identical rows after explicit user acknowledgment. Neither mode infers evidence freshness, authentic ownership, a fix, retest or permission.
- Validate the **entire newly constructed original v1 workplan** through unchanged `_load_resume_bytes` against the later original source, before any output. Complete new membership, exact digest and original fields, source-independent banned authority flags set literally false. Size capped at the original 256 KiB `MAX_PLAN`.
- `carry` prompts for an independent fresh output secret (passphrase not supplied on command line); publishes **one new 0600 non-overwriting AES-256-GCM `.lun`** through the existing atomic original publisher. No intermediate plaintext JSON or HTML is written. Original source and plan remain untouched.
- `preview` prints ID-free counts. Optional acknowledged source-bound portable scriptless HTML contains only anonymous category/declared-severity counts, not private original client IDs, paths, titles, finding IDs, aliases, notes, source digests or remediation texts. HTML is **unencrypted** and still recipient-sensitive.
- No persistence other than an explicitly requested local output; no network, scanner, authentication bypass, consent, grants, claims of repaired findings, retests, recipient uploads or browser storage.

**Critical limitation:** unchanged five-column CSV content cannot demonstrate that *underlying finding evidence*, timestamps, asset identity, source provenance, or real approval stayed the same. Human review is always needed before acting on any copied coordination field. Source-export checksums and ciphertext authentication do **not** authenticate the sender's real identity, independently verify true findings, or authorize live action. Existing encrypted browser Handoff Vault #1640 uses another format.

## Operator commands

Run from the checkout of this branch with the same dependencies as original parent PR #1647. Enter three secrets interactively (earlier original source, earlier exact-source HUMAN plan, later original source).

```sh
python -m lightup.private_export_human_revision preview \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --ack-private-handling --ack-same-real-client
```

Portable anonymous private HTML review report (a real **unencrypted** file; do not email without separate recipient/security approval):

```sh
python -m lightup.private_export_human_revision preview \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --output /private/revision-review.html \
  --ack-private-handling --ack-same-real-client --ack-plaintext-html
```

Create a **new** encrypted HUMAN plan, preserving only owner alias and private note on fully unchanged original exported rows:

```sh
python -m lightup.private_export_human_revision carry \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --output /private/later-human.lun \
  --ack-private-handling --ack-same-real-client --ack-human-carryover
```

If the human reviewer deliberately chooses to carry **unverified HUMAN** proposed stages/dates for rows with exact five-column equality, append these flags to the `carry` command:

```text
--carry-stage --ack-human-stage-carryover
```

Alternatively, open the separate foreground menu:

```sh
python -m lightup.private_export_human_revision_console
```

The original **parent** source export and workdesk console remains unmodified. The new resulting `.lun` can be used against `later.lue` in the original encrypted notes workdesk, and all existing original admission checks still apply:

```sh
python -m lightup.private_export_encrypted_notes workdesk \
  /private/later.lue /private/later-human.lun \
  --output /private/new-human-workdesk.html \
  --ack-private-handling --ack-plaintext-html
```

## Delivery and release boundary

All use is **operator-run on previously exported private files**. Protected storage, true identity, actual consent and handling authority must be independently established; the human-directed acknowledgment switches are **not** security gates for active testing. No original source file, grant, persisted finding, retest state, branch-owner source, test suite, CI workflow or deployment is changed.

Project posture is **Notion Incubate · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD**. No main merge, production deploy or active target work until pre-existing original exact-head hosted and permanent named VPS CI, original source-owner acceptance, independent security/privacy/cryptography review, real separately authenticated client and operator consent including use-time revocation, original issues #177/#182/#829, and explicit HUMAN GO. A local encrypted plan is never a client authorization token or verified remediation record.
