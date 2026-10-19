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
