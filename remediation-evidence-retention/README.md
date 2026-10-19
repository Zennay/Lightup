# LightUp · PRIVATE Evidence Retention Review

**Incubate · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** This is a human-only, source-bound retention *review calendar* for extracted private evidence; it never deletes a file, grants access, certifies a finding or authorizes a retest. No release/production merge without original exact-head hosted + registered permanent VPS CI, original source-owner approval, independent privacy/security/cryptography review, separately authenticated current client/operator consent with action-time revocation, and explicit HUMAN GO. Original #177/#182/#829 remain separate release blockers.

## What is built

The original [encrypted actual evidence transfer](../remediation-evidence-materials/README.md) already emits a canonical private `PRIVATE-receipt.json` plus `material-01.bin` etc. The new **`retention.py`** consumes *those actual bytes*, not a standalone invented mockup. For every operation it:

1. Uses the unchanged original `DomainStore` account login and exact current client/engagement source, then decrypts the existing original PRIVATE HUMAN workroom after a terminal-only passphrase prompt.
2. Admits the original native receipt with canonical JSON, exact source SHA, literal-false authority flags, exact original indexed finding ID / SHA / file name / byte length and **every actual local 0600 file byte**. Directory must be a real owner-private 0700 directory; extra files are refused.
3. For `stage`, prompts the human for each neutral file's review status (`retain_pending_review`, `legal_hold`, or `review_for_deletion`), a canonical next human review date and optional bounded private note. These are **advisory HUMAN states**, never erasure/hold determinations by a court or privacy officer.
4. Seals the entire record in **a new exclusive 0600 AES-256-GCM/PBKDF2 `.ltv`** using the unchanged original vault. The new passphrase must differ from the original HUMAN workroom secret; no plaintext plan is stored by the CLI.
5. `renew` reopens the previously encrypted plan alongside the **current** original source and rechecks all actual file bytes, pre-fills HUMAN review decisions, permits explicit `<clear>` of old private notes, and seals a NEW distinct encrypted `.ltv` with a third, different passphrase. Original source/material/earlier plan remain untouched.
6. `inspect` reauthenticates current account/client/source, verifies ALL original files, opens the encrypted plan, checks receipt identity and prints only total/due counts. `open-current` does the same and emits a NEW 0600 static private HTML review table with no scripts, network, browser storage or remote assets. Expired dates merely show **HUMAN REVIEW DUE**; they never trigger deletion.

Nothing touches the LightUp domain/source-owner files, scans, grants, original encrypted vault, extracted material, persisted findings or live targets. This add-on only owns `remediation-evidence-retention/`.

## Usage — private trusted Linux workstation

Run in a private terminal from the **exact source-compatible parent branch** with the original transfer, HUMAN workroom and material folders already provisioned. Each operation prompts for the original private HUMAN passphrase. `stage` also prompts for a **different new** retention-plan passphrase; `inspect` and `open-current` prompt for the existing plan passphrase. No passwords in shell arguments.

```sh
python3 remediation-evidence-retention/retention.py stage \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --output /private/retention-review-v1.ltv \
  --ack-private-material

python3 remediation-evidence-retention/retention.py inspect \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --plan /private/retention-review-v1.ltv \
  --ack-private-material

python3 remediation-evidence-retention/retention.py open-current \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --plan /private/retention-review-v1.ltv \
  --output /private/retention-review-v1.html \
  --ack-private-material
```

All operations require a real interactive terminal, original matching private files and explicit private-data acknowledgement. Output path must be a **new** owner-private path. Never open the generated private HTML on an untrusted/shared device, send it to a cloud service, or treat it as a release artifact. Explicitly back up and handle original evidence according to an independently approved retention policy; this tool performs no wiping, secure erase, device revocation or actual legal-hold issuance.

To revise an already-staged human plan while keeping the original immutable:

```sh
python3 remediation-evidence-retention/retention.py renew \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --plan /private/retention-review-v1.ltv \
  --output /private/retention-review-v2.ltv \
  --ack-private-material
```

`renew` refuses passphrase reuse against the original HUMAN vault **and** the previous retention plan, requires current native source-and-bytes continuity, and never overwrites the old encrypted plan. A blank decision or note keeps the previous human input; `<clear>` explicitly removes a former human note. An old due date requires selecting a new nonpast date when reissuing. Changing an earlier HUMAN `legal_hold` label to another HUMAN label requires a **separate exact terminal confirmation** and still never authorizes an actual legal-hold release; all freeform private HUMAN notes reject unsafe control/format/bidi characters before encrypted sealing or private display. No silent renewal or legal policy determination occurs.


## Multi-version PRIVATE HUMAN review history

The new [`history.py`](history.py) integrates the previous commands: it accepts **2–12 existing DISTINCT encrypted HUMAN retention plans**, reauthenticates the original CURRENT LightUp account/tenant/engagement, admits the unchanged encrypted original HUMAN source, checks the **entire actual material receipt and original file bytes**, then opens each encrypted plan with its own private terminal prompt. It refuses modified/duplicate plans, source drift, original inventory changes, malformed authority flags or unauthorized local files before creating output.

The result is a **NEW owner-only 0600 local no-network, no-script HTML reviewer history** with first/current human state, dates, per-file revision change steps, review-due counts and a separately highlighted caution whenever a HUMAN `legal_hold` is changed to another HUMAN status. It does **not** release a legal hold, prove that a legal hold was valid, or delete evidence. Input **ordering is selected by the human**, not an authenticated historical time sequence. No browser storage, private report cloud sync, or original record changes.

```sh
python3 remediation-evidence-retention/history.py \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --plan /private/retention-review-v1.ltv \
  --plan /private/retention-review-v2.ltv \
  --output /private/private-retention-history.html \
  --ack-private-material
```

Private encrypted plan filenames and source material should not be shared with third parties. Terminal output only contains counts; original finding identities and encrypted-input SHA-256 appear only in the private HTML. This is an independent HUMAN coordination capability, never provenance verification or an action-time grant.


## Native HUMAN Request Desk handoff — live review workflow, never automatic Apply

New [`request_handoff.py`](request_handoff.py) bridges **actual due** owner-private encrypted retention entries into the unchanged original LightUp native HUMAN Request Desk schema, instead of keeping due work stranded in a local calendar. Every command invokes the original current `DomainStore` authentication and current client/engagement source, decrypts the exact current original PRIVATE HUMAN workroom and encrypted retention plan, and admits the entire original 0600 evidence receipt plus all actual indexed private file bytes.

**`preview`** shows only counts: finding groups with due HUMAN review dates, groups blocked by already-open original HUMAN requests, and fresh eligible groups; no new file, ID or request created. **`stage`** requires the operator to choose distinct *numbered* eligible finding groups, then type a separate explicit acknowledgement. It stages a bounded original-native `followup_question` with `human_stage=draft`, preserving all original Casework, evidence-review, attachments and prior original HUMAN requests unchanged; never inserts a second live original request for the same finding, silently trims human notes, or claims authorization/deletion. Review question text points to independent verification of any applicable retention policy; it contains only bounded source references and HUMAN counts/dates, **not** original private freeform notes. Result is a **new original-compatible private 0600 AES-GCM/PBKDF2 HUMAN workroom**, with a new passphrase distinct from both original HUMAN and retention-plan secrets.

```sh
python3 remediation-evidence-retention/request_handoff.py preview \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --plan /private/retention-review-v2.ltv \
  --ack-private-review

python3 remediation-evidence-retention/request_handoff.py stage \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --plan /private/retention-review-v2.ltv \
  --output /private/retention-native-human-drafts.ltv \
  --ack-private-review
```

The original HUMAN application must still perform its **own current source-bound Preview and explicit manual Apply**. This helper writes only a different, owner-private encrypted file, not an original database row or original workspace in-place. Even where an operator later decides a retention entry is reviewed, this workflow **does not delete, release legal holds, certify evidence/retests, verify client consent or issue scanner authority**.


## Complete PRIVATE retention + original Casework desk

Use [`desk.py`](desk.py) when an operator needs more than a spreadsheet-like retention queue. It performs **one original current-account/tenant/engagement source read**, decrypts the existing original HUMAN workroom, checks the complete original extracted 0600 evidence receipt and every real file hash, opens the latest encrypted HUMAN retention plan and creates **one entirely new owner-private 0600 local scriptless HTML desk**. The desk combines due/soon/later retention attention, human-marked legal holds, original HUMAN Casework status, original Evidence Review state, existing open HUMAN request counts and safe eligibility for fresh manual follow-up questions. It groups all actual material by original finding and links to private sections using scriptless local anchors.

Optional **`--include-private-casework`** deliberately includes existing unverified original HUMAN Casework notes and the new plan's private notes inside that PRIVATE HTML; omitted by default. This is *offline static presentation*, never a signed audit record, original restoration, data deletion or proof that a hold/permission applies.

```sh
python3 remediation-evidence-retention/desk.py \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --plan /private/retention-review-v2.ltv \
  --output /private/retention-operations-desk.html \
  --ack-private-material
```

## Original HUMAN Request Desk return reconciliation

[`reconcile.py`](reconcile.py) completes the operator's **human-only status tracking** once an original native staged follow-up exists. It freshly reauthenticates original client/engagement access and checks the original complete actual evidence byte inventory and encrypted retention plan. It then decrypts both the **staged original-compatible encrypted HUMAN draft** created by `request_handoff.py stage` and a **separately supplied later native HUMAN workroom**. It rejects source drift, malformed native HUMAN collections, re-bound request identities, changed original fingerprint inventory and altered original draft baseline. New staged request IDs are checked against genuine due original indexed evidence; any later packet is matched by the exact original request UUID, finding, fingerprint and type.

`inspect` only prints anonymous counts; `publish` emits a new 0600 offline no-network HTML, showing each source-reported HUMAN status transition, missing stage records and changed human text (without exporting the complete private response text). A supplied later HUMAN file is **not proof of native Apply**, verified consent, record provenance, client signoff, actual deletion, legal-hold release or remediation success.

```sh
python3 remediation-evidence-retention/reconcile.py inspect \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --plan /private/retention-review-v2.ltv \
  --drafts /private/retention-native-human-drafts.ltv \
  --later /private/later-original-human-workroom.ltv \
  --ack-private-review

python3 remediation-evidence-retention/reconcile.py publish \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id <original-client-id> --engagement-id <original-engagement-id> \
  --human /private/existing-human.ltv \
  --directory /private/received-material \
  --plan /private/retention-review-v2.ltv \
  --drafts /private/retention-native-human-drafts.ltv \
  --later /private/later-original-human-workroom.ltv \
  --output /private/retention-human-followup-continuity.html \
  --ack-private-review
```

The later workroom must be legitimately provided by an existing independent original-human collaboration step, and all passphrases entered in a private interactive TTY. Operator-provided ordering and claimed status are never substituted for genuine action-time consent or proof of execution. The source-owner evidence collector, finding export, scanner, grants, and original request handlers remain unmodified.

## Ownership and acceptance posture

**Base:** immutable [#1657](https://github.com/Zennay/Lightup/pull/1657) source snapshot `0c2f2689ad5862eb7372d9bf2ed3aa81831f43c4`, unchanged. Owner's subsequent commits are not silently assimilated. Added paths are independent from `remediation-evidence-materials/`, evidence transfer owners and issue #1182 CSV source owners. Release gates unchanged.

Direct permitted zSSH only: the new CLI compiled and `--help` resolved in a separate checkout. **No QA/regression/test suite, synthetic authority proof, actual customer data, scan, target access, CI rerun or production deployment** has been performed. Functional authorization and encrypted real-data round trip remain unverified without legitimate private data, independent owner reviews and existing gates.
