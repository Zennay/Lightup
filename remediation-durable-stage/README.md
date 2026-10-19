# LightUp PRIVATE Durable HUMAN Stage (DRAFT/HOLD)

An add-only, single-machine operator workflow for the **original** authenticated encrypted HUMAN Evidence Ledger, PRIVATE actual evidence material, and HUMAN retention plans in held parents [#1657](https://github.com/Zennay/Lightup/pull/1657) and [#1658](https://github.com/Zennay/Lightup/pull/1658).

## Product behaviour

This CLI maintains a local, owner-private journal keyed to the **current original source + actual material receipt + client/engagement** (not the retention-plan revision). It admits the original current account/client/engagement, original encrypted HUMAN workroom and retention review, and **all actual 0600 file bytes** before every operation. A source/attachment change fails closed.

- `status` displays only anonymous HUMAN counts, latest stage state and whether original HUMAN closure is recorded. It does not publish evidence.
- `stage` interactively selects original due HUMAN finding groups, performs a *second current original authentication + complete actual evidence re-read*, then persists an fsynced `pending` intent **before** writing the new 0600 original-native AES-GCM encrypted HUMAN draft. The same source/material cannot be restaged from this journal while `pending` or `staged`.
- `recover` handles an interrupted `pending` operation **only** by opening the exact existing encrypted native draft, verifying native original-source admission and all recorded request identities, then recording the encrypted file fingerprint. No plaintext HUMAN workspace is created.
- `resolve` requires each exact previously staged native request be present as `closed_human` in the **current original HUMAN workroom**, checks unchanged encrypted draft bytes, and obtains separate human confirmation before permitting a later cycle. An interrupted pending stage without any file at the recorded path may be marked aborted *only* after explicit human inspection; any existing unidentified encrypted output stays HOLD.

This is LOCAL coordination, not authenticated reviewer identity, proof that native Apply occurred, legal-hold release, client consent, active-scan grant, evidence custody certification, deletion or remediation verification. It cannot prevent staging with another command, journal directory or device. It is **not a distributed lock** or product-wide admission gate.

## Operator steps (trusted private Linux workstation only)

Use a pinned compatible parent branch with a real original authorized account, original encrypted HUMAN Evidence Ledger, retention plan and extracted 0700 PRIVATE material folder containing its canonical receipt and unchanged material files.

Create a **different** existing owner-private 0700 journal folder (not inside the original material folder):

```sh
mkdir -m 700 /private/my-human-journal
```

Every command needs these arguments; use literal values on a private terminal. Passphrases are prompted securely, not supplied as CLI flags.

```sh
python3 remediation-durable-stage/journal.py status \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id ORIGINAL_CLIENT --engagement-id ORIGINAL_ENGAGEMENT \
  --human /private/original-human.ltv \
  --directory /private/extracted-material \
  --plan /private/retention-review.ltv \
  --journal-dir /private/my-human-journal --ack-private-material
```

For `stage`, use the same parameters and append `--output /private/new-native-human-drafts.ltv`. To recover a crash after the encrypted file was written but before its journal entry was finalized, use `recover` with the common parameters. For closeout use `resolve` with the common parameters, changing `--human` to a **separately received current original HUMAN workroom** that contains each exact recorded request with a HUMAN-reported `closed_human` status. Inspect that source independently; status is unverified.

The operator still separately opens the original Request Desk, runs its original source-bound Preview and performs manual HUMAN Apply as appropriate. Nothing here executes that step. PRIVATE journals include absolute local encrypted-output paths and hashes and MUST remain owner-private; do not sync them.

## Release fence

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** No main merge, production deploy, scan, grant, retest or QA rounds from this add-on. Original exact-head hosted and registered permanent named VPS CI, original source-owner and independent security/privacy/browser/crypto review, #177/#182/#829, genuine separately authenticated current client/operator consent with action-time revocation and explicit HUMAN GO are still required.
## Offline local HUMAN chronology

The optional `report` subcommand accepts the same source, journal and
`--ack-private-material` options as `status`, plus a distinct NEW output:

```sh
python3 remediation-durable-stage/journal.py report \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id ORIGINAL_CLIENT --engagement-id ORIGINAL_ENGAGEMENT \
  --human /private/original-human.ltv \
  --directory /private/extracted-material \
  --plan /private/retention-review.ltv \
  --journal-dir /private/my-human-journal \
  --output /private/private-human-chronology.html --ack-private-material
```

After full ORIGINAL current source and real material admission, it exclusively
publishes an owner-private 0600 scriptless, no-network HTML with local cycle
timestamps, HUMAN states, counts, latest suggested operator action and explicit
unknown-authority warnings. It contains no client/finding/request identity,
fingerprint, source/evidence bytes, private notes, password or local file path.
The chronology is just locally reported HUMAN state, not an authenticated
audit trail or signed security outcome; never sync it or treat it as release
authority.

## Original native HUMAN delivery: see exactly what happened to drafts

The local journal now includes a source-current, privacy-minimal ORIGINAL
Request Desk delivery comparison. It opens the exact SHA-256-matching original
encrypted `staged` HUMAN workroom with a separate private passphrase prompt,
admitting that ORIGINAL native schema alongside the CURRENT separately
provided encrypted original HUMAN workroom and all original evidence bytes.

- `review` prints per-request **neutral ordinals** and aggregate HUMAN states:
  `not_observed`, `draft`, `closed_human`, or the original approved HUMAN
  enum, together with whether the HUMAN request text/response was edited.
- `review-html` writes an exclusive 0600 PRIVATE, scriptless/no-network
  offline browser dashboard with anonymized per-request state, assignment,
  response-present indicator, HUMAN content-change indicator and aggregate
  remaining-unclosed attention.
- `resolve` now also decrypts/re-admits the recorded original-native staged
  encrypted workroom and requires *exact recorded request identity continuity*
  and all corresponding CURRENT original HUMAN entries reporting closed_human.
  The reported HUMAN labels do not prove actual native Apply, signed user
  identity, that the source owner authenticated the change, or client consent.
- Every source-bound encrypted input, new native draft, private report and
  local journal MUST reside beneath a real owner-private 0700 parent (no
  symlinked directory ancestors). Missing/malformed/corrupt source material
  HOLDs; no source mutation or automatic deletion is attempted.

Example after independently obtaining the CURRENT original encrypted HUMAN
workroom, replacing the `--human` argument with that newly provided workroom:

```sh
python3 remediation-durable-stage/journal.py review \
 --db /private/lightup.db --email operator@example.invalid \
 --client-id ORIGINAL_CLIENT --engagement-id ORIGINAL_ENGAGEMENT \
 --human /private/current-original-human.ltv \
 --directory /private/extracted-material \
 --plan /private/retention-review.ltv \
 --journal-dir /private/my-human-journal --ack-private-material

python3 remediation-durable-stage/journal.py review-html \
 --db /private/lightup.db --email operator@example.invalid \
 --client-id ORIGINAL_CLIENT --engagement-id ORIGINAL_ENGAGEMENT \
 --human /private/current-original-human.ltv \
 --directory /private/extracted-material \
 --plan /private/retention-review.ltv \
 --journal-dir /private/my-human-journal \
 --output /private/current-human-delivery.html --ack-private-material
```

Never send this report or any decrypted HUMAN workroom to a shared/cloud
service. The comparison reports only what the separately supplied current
original HUMAN workroom *says*, not authenticated execution or third-party
approval. Every report is a distinct new private file, not an overwrite.

## One-terminal PRIVATE original HUMAN operator console

A cohesive **interactive HUMAN operations menu** is now available, wrapping
the same original source-admitted `journal.main` actions. Each selection
performs a **new** original current account/tenant/engagement read, reopens
the current native encrypted HUMAN workroom + retention plan with individual
private passphrase prompts and checks all actual PRIVATE evidence bytes.
It does not cache earlier admission as a later grant.

```sh
mkdir -m 700 /private/local-human-console-output
python3 remediation-durable-stage/human_console.py \
  --db /private/lightup.db --email operator@example.invalid \
  --client-id ORIGINAL_CLIENT --engagement-id ORIGINAL_ENGAGEMENT \
  --human /private/current-original-human.ltv \
  --plan /private/current-retention-plan.ltv \
  --directory /private/extracted-material \
  --journal-dir /private/my-human-journal \
  --output-dir /private/local-human-console-output \
  --ack-private-material
```

The console provides original source/journal status, native encrypted draft
staging, encrypted-draft recovery, ORIGINAL HUMAN delivery comparison, private
delivery HTML, private chronology HTML, source-checked reported-human closeout,
and verified switching between separately supplied original-native HUMAN
workrooms or retention-plan revisions without leaving the terminal. New
PRIVATE outputs are exclusive, randomly named 0600 files in a **separate**
0700 owner-private output directory. No original material files or journal
entries may share that output directory.

An additional within-session fence refuses a second staging after a completed
stage in the same interactive console, even if a different plan/workroom is
chosen. This is not a distributed or cross-device queue; other local tools
remain outside it. For current original HUMAN workroom switching, the console
first performs an entire fresh original source admission **before** changing
its own selected path. A rejected candidate leaves the old selected source
unchanged. This console does not itself invoke native Apply or prove an
underlying HUMAN answer is true, authorized, signed or legally sufficient.
It never scans, retests, deletes, grants or deploys.
