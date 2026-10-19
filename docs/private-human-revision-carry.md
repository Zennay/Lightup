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

## Private original-ID HUMAN source reconciliation queue (second delivered product)

The separate `python -m lightup.private_export_human_revision_workqueue` command performs the **same three complete source/workplan admissions** and requires a separate manual acknowledgment before saving an **unencrypted**, mode-0600 original-ID/title HTML briefing. This provides the human operator a real source-change queue organized into four sections: changed source fields (with changed column names, no old/new remediation text), newly present findings, absent records (explicitly NOT fixed), and exact five-column matches eligible for optional HUMAN coordination carry. Entries prioritize changed critical/high records and include original finding IDs, titles, severity and the *earlier unverified HUMAN stage/note presence only*. It **never** includes plaintext private HUMAN notes, actual owner aliases, client labels, source hashes, targets, remedies, source evidence or consent data.

```sh
python -m lightup.private_export_human_revision_workqueue \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --output /private/original-id-source-review.html \
  --ack-private-handling --ack-same-real-client \
  --ack-original-ids-plaintext
```

The separate interactive foreground console also exposes this workflow as menu **5**; choose menu 2 if an ID-free summary is sufficient. No HTML files are encrypted. The customer recipient and private storage must be independently verified. Source-row equality is NOT equivalence of missing/non-exported evidence. This queue is not a security retest, proof of fixes or a resolution workflow.

### Additional source-chronology sanity condition

In addition to the real-client human acknowledgment and strict matching self-declared client/engagement, `preview`, `carry` and the detailed workqueue **HOLD** if the later original archive's declared `generated_utc` timestamp is not strictly newer than the earlier original export in UTC. This prevents accidental backward movement in a source-revision handoff. The timestamp is only a **self-declared** sanity check and cannot prove actual temporal order or genuine source ownership.

## Selective HUMAN per-finding approval — usable new workflows

The original one-step `carry` and the historical private workqueue remain available. The **new selective workflow** does not silently carry all matching records: each of the original new-source finding rows begins with both HUMAN migration approvals literally **false**. It offers two operator routes using exactly the unchanged original encrypted source readers and v1 original workplan parser.

### Route A: private source-bound editable decision sheet

First produce a new **unencrypted private 0600 JSON** for a real human to review. Every row contains the original ID, potentially identifying title, source-claimed severity, five-column original record SHA-256, and one of `five_column_identical`, `changed`, or `new`. **No private HUMAN notes or aliases, remediation body or raw source evidence are exported.** All human choices default to false; disappearing original IDs are omitted rather than misrepresented as repaired. This is a private work document; secure handling and real recipient verification are required.

```sh
python -m lightup.private_export_human_revision_choices prepare \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --output /private/revision-decisions.json \
  --ack-private-handling --ack-same-real-client \
  --ack-plaintext-original-ids
```

The human may edit **only** the boolean `copy_owner_and_note` and `copy_stage_and_due` for each `five_column_identical` row. Every other header, field, source digest, exact row digest, row sequence, original title, severity, and classification must remain unchanged. Setting `copy_stage_and_due=true` also requires `copy_owner_and_note=true`. It is prohibited to approve any change/new source row. A review document is **not** an authorization, verified client identity, test consent, security attestation or evidence of remediation.

After an independent human review, import the exact source-bound choices, confirm them explicitly and create **one new encrypted `.lun`** against the new original source; no intermediate plaintext workplan is written. The choices file must be regular, no-follow and owner-private (`0600` or stricter). A late mismatch (original source, order, digest, classification, forbidden status, malformed JSON, unsafe file permissions, altered title, duplicate keys, missing rows) refuses the entire operation **before** any output.

```sh
python -m lightup.private_export_human_revision_choices apply \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --choices /private/revision-decisions.json \
  --output /private/reviewed-later-human.lun \
  --ack-private-handling --ack-same-real-client \
  --ack-manual-human-decisions
```

### Route B: in-terminal approval without a plaintext decision sheet

The alternative `private_export_human_revision_guided` requires a trusted interactive terminal, loads/decrypts the three original files and prompts **once for every five-column-identical record**, displaying the original ID/title/severity and prior HUMAN stage plus whether a private note exists. It does not show note content. The human must enter exactly one of `SKIP`, `OWNER`, `OWNER_AND_STAGE`, or `QUIT`: omitted decisions, invalid inputs, cancellation and EOF fail closed without a new output. Changed/new rows cannot prompt or carry. Following the final decision, the original complete plan is re-admitted and published as a fresh 0600 encrypted `.lun` with a separately entered passphrase. **No intermediate plaintext decision file** is produced.

```sh
python -m lightup.private_export_human_revision_guided \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --output /private/guided-human.lun \
  --ack-private-terminal --ack-same-real-client \
  --ack-human-decisions
```

The existing isolated menu now offers choice-sheet export **6**, strict choice-sheet import **7** and terminal-by-terminal guarded HUMAN review **8**; the parent source-owner console remains unchanged.

### Reuse of the resulting real original HUMAN plan

Both selective routes produce the same authenticated-AES envelope and original plan schema as the separately owned `private_export_encrypted_notes` consumer. Operators can use the parent unchanged `workdesk` route for the **later** original `.lue` and newly created `.lun`, only with independent private recipient/storage approval. Outputs cannot establish genuine client identity, authentication freshness, user consent, evidence equality, effectiveness of a fix, or authority for scanning. Original release HOLD remains binding.


### Route C: portable PRIVATE offline browser editor (new visual product)

The new `private_export_human_revision_editor` consumes the **same original three encrypted files** and produces a single-file, self-contained, 0600 **UNENCRYPTED** HTML application. Its per-finding decisions begin FALSE. An operator can search original findings, filter unchanged/changed/new rows, explicitly choose owner/note and optional HUMAN stage/date independently for **each eligible unchanged five-column original source row**, clear all choices, and download the same source-bound original JSON sheet as Route A. Changed/new records stay disabled, and stage/date stays disabled until owner/note is selected. There is deliberately no bulk-approve action.

```sh
python -m lightup.private_export_human_revision_editor \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --output /private/visual-human-revision.html \
  --ack-private-handling --ack-same-real-client \
  --ack-plaintext-original-ids
```

The local browser editor embeds **private original finding IDs/titles and self-declared client/engagement/source hashes** so it must be treated as sensitive plaintext, even if it never displays earlier private HUMAN notes/aliases or raw remediation/evidence. No remote resources, HTTP requests, storage API, cookies or external scripts. Its inline CSS and JavaScript have exact SHA-256 CSP hashes, and all potentially untrusted source text is placed into safe browser `textContent`, never `innerHTML`. Generated JSON is held in browser memory until an explicit human export with an additional acknowledgment. **The JSON download itself is UNENCRYPTED**; ensure private owner-only file permissions before `choices apply`, as browsers cannot guarantee download permissions.

After visually editing and saving the choice sheet, run the unchanged **Route A `apply`** command with all three original encrypted inputs, the exported JSON, and a new `.lun` destination. All original source-bound admission, duplicate-key handling, no-follow owner-private JSON input and new encrypted output conditions still apply. The visual editor is also available as separate console option **9**. This visual UI is only an offline human coordination interface — neither the CSP hash nor an original-source checksum authenticates actual clients, verifies findings/fixes, or grants permission.


## Encrypted private decision custody: separate AES-256-GCM `.lud` product

The new, fully offline `private_export_human_revision_vault.py` provides a real private custody route for manual selected HUMAN revision decisions. It adds a **distinct** authenticated `.lud` (LightUp HUMAN decisions) format, separate from the original encrypted finding source `.lue`, HUMAN workplan `.lun`, owner exchange and independently owned encrypted history `.luh`. It reuses the pinned parent original AES-256-GCM/scrypt readers and writer; no cloud transport, network, tenant account or new authorization path.

### Why and how

The offline browser editor intentionally downloads a sensitive, plaintext original-ID/title/declared-source JSON selection sheet. Even when saved with owner-only permissions, this remains a plaintext privacy risk for manual human handoffs. After the operator has independently inspected and approved the exact original source and client/recipient handling, **`seal` encrypts the selected JSON** into a new 0600 `.lud` with a different magic/version and separately prompted passphrase. It validates the **entire original ordered decision document against all three original encrypted inputs** before creating ciphertext.

The recipient can later **`inspect`** the same `.lud` against the independently provided original earlier `.lue`, earlier source-bound `.lun`, and later `.lue`, receiving only aggregate HUMAN carry counts. **`apply`** decrypts and verifies the `.lud` entirely in memory and directly produces a NEW original-format, exact-later-source encrypted `.lun`, using a separately entered passphrase, without writing an intermediate plaintext workplan or decision JSON. **`rotate`** independently re-encrypts exactly the same admitted decision bytes with fresh salt, nonce and passphrase into a different, non-overwriting `.lud`. **`open`** is an explicitly acknowledged recovery workflow that writes a NEW unencrypted private `.json` for an independently verified human recipient only; it is never implicit.

The ciphertext reader uses one descriptor with Linux `O_NOFOLLOW`, requires owner-private regular files (0600 or stricter) and enforces the original 256 KiB decisions limit plus authenticated envelope overhead. The original three sources and prior plan undergo their **original existing admission**, and each decision is reconciled against the original complete ordered five-column record list, literal-false authority flags, digest, declared client/engagement and date. An invalid source, passphrase, missing or changed original row, rejected choice, non-private/symlinked file, unknown version, partial file or invalid destination returns HOLD before creating a final output. **A checksum or authenticated ciphertext protects local integrity; it does not authenticate a real source sender, finding truth or actual client consent.**

### Operator commands

Run from the local working Python package on a trusted terminal. Original source passphrases, earlier plan secret, new decision secret and later new plan secret are each entered using the existing interactive passphrase prompts rather than CLI arguments. The three input files are original encrypted earlier source, earlier exact-source HUMAN plan, and later encrypted source in that order.

```sh
# After reviewing original IDs, fix any browser download permissions first:
chmod 600 /private/reviewed-decisions.json

# Encrypt the approved ORIGINAL source-bound decisions in a NEW .lud.
python -m lightup.private_export_human_revision_vault seal \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --choices /private/reviewed-decisions.json \
  --output /private/reviewed-decisions.lud \
  --ack-private-handling --ack-same-real-client --ack-human-decisions

# Reopen and re-admit complete encrypted decisions; no plaintext artifact.
python -m lightup.private_export_human_revision_vault inspect \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --encrypted-choices /private/reviewed-decisions.lud \
  --ack-private-handling --ack-same-real-client

# HUMAN-approved decisions -> directly to NEW encrypted original .lun.
python -m lightup.private_export_human_revision_vault apply \
  /private/earlier.lue /private/earlier.lun /private/later.lue \
  --encrypted-choices /private/reviewed-decisions.lud \
  --output /private/approved-new-human-plan.lun \
  --ack-private-handling --ack-same-real-client --ack-human-decisions
```

A separate `rotate` command accepts `--encrypted-choices SOURCE.lud --output NEW.lud` and both general acknowledgments; an exceptional `open` command accepts `--encrypted-choices SOURCE.lud --output NEW.json --ack-unencrypted-original-ids` as well. Both read and validate the original three sources before any output. All new files use exclusive non-overwriting 0600 atomic private publication; deleting old plaintext or ciphertext is a separate conscious operator decision, never automated.

The isolated revision operator menu exposes the five actions as **10–14**, alongside the original offline browser/terminal HUMAN workflows. The prior original-export console is unchanged.

**Privacy reminder:** Encrypting the approved JSON does not erase the previously downloaded plaintext decision sheet or the unencrypted offline browser page. A secure reviewer must independently handle its retention, deletion, and recipient/transport. The `.lud` ciphertext is still sensitive and does not grant authority, attest fixes, establish authentic client identity, validate missing evidence or permit scans/retests.

**Release posture:** Notion `Incubate`, M3/M7 PLAN/LAB ONLY, DRAFT/HOLD. Parent PR #1647, original source-owner and original hosted + permanent named VPS CI, independent security/privacy/crypto approvals, real distinct authenticated client/operator consent with at-use revocation, original issues #177/#182/#829 and explicit HUMAN GO must be cleared before any main merge or production deployment. No QA/regression/testsuites were introduced or run.
