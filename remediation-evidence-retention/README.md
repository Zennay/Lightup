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

`renew` refuses passphrase reuse against the original HUMAN vault **and** the previous retention plan, requires current native source-and-bytes continuity, and never overwrites the old encrypted plan. A blank decision or note keeps the previous human input; `<clear>` explicitly removes a former human note. An old due date requires selecting a new nonpast date when reissuing. No silent renewal or legal policy determination occurs.


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

## Ownership and acceptance posture

**Base:** immutable [#1657](https://github.com/Zennay/Lightup/pull/1657) source snapshot `0c2f2689ad5862eb7372d9bf2ed3aa81831f43c4`, unchanged. Owner's subsequent commits are not silently assimilated. Added paths are independent from `remediation-evidence-materials/`, evidence transfer owners and issue #1182 CSV source owners. Release gates unchanged.

Direct permitted zSSH only: the new CLI compiled and `--help` resolved in a separate checkout. **No QA/regression/test suite, synthetic authority proof, actual customer data, scan, target access, CI rerun or production deployment** has been performed. Functional authorization and encrypted real-data round trip remain unverified without legitimate private data, independent owner reviews and existing gates.
