# LightUp · Isolated-lab batch launchpad

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** New-only `assessment-launchpad/` product pinned to original held CLI source commit `74e865201c8a4270e404046ef3447eb7f190edfb`. The original source owner, CLI, `_admit_explicit_lab_url`, `LabScenario`, and `ScopePolicy` files are not modified.

## Browser composer

Open `composer.html` locally. It is one standalone file with a strict hash-pinned CSP (no unsafe-inline script/style) and no external assets, APIs, storage, DNS or network access. Compose 1–16 distinct literal HTTP(S) URLs within the native CLI\'s 16 KiB manifest limit, or import a private existing local manifest. Import is all-or-nothing (strict UTF-8, no BOM/NUL, no duplicate values); failed imports retain the current editor. Edit/remove/reorder endpoint slots before clicking **Download private text manifest**. Nothing is uploaded or saved to browser storage. Browser checks are convenience-only and do not prove an endpoint is isolated.

Browser downloads cannot set file permissions. Before using the native CLI, move the downloaded file to a private directory and set mode `0600`. Use this PR branch (not the older source-only pinned ancestor), for example `git fetch origin chatgpt/lightup-assessment-launchpad-20261021-gpt6` followed by `git switch --detach FETCH_HEAD` in a disposable trusted checkout. The CLI refuses any modified original pinned validator or CLI bytes.

## Native validator-backed handoff

Requires a checkout of this launchpad PR branch, which contains both `assessment-launchpad/` and the original source files at the frozen source pin, with the existing project Python dependencies. Checking out the pinned ancestor commit **alone will not work** because that older commit does not contain the launchpad. Create an owner-only output directory separate from the manifest directory:

```bash
chmod 600 ~/Downloads/lightup-lab-targets.txt
mkdir -m 700 ~/private-lab-launchpad-output
python3 assessment-launchpad/launchpad.py \
  --manifest ~/Downloads/lightup-lab-targets.txt \
  --output-dir ~/private-lab-launchpad-output
```

The CLI checks the Git blob hashes of the pinned original `cli.py`, `labrun.py`, `labeval.py`, `scope.py` and `models.py` before loading the original `_admit_explicit_lab_url` and `LabScenario`. `LabScenario` invokes the original isolated loopback/private-lab `ScopePolicy`. No DNS resolution or target connection is made.

The command requires an owner-owned input regular file with mode `0600`, no symlink/hard-link alias, bounded stable contents (16 KiB), and 1–16 distinct endpoints. The output directory must already exist, be owned by the current user and have mode `0700`. Outputs are exclusive no-overwrite files with mode `0600`; failed bundle publication removes newly created outputs.

The output directory receives five private artifacts:

- `lightup-lab-targets.txt` — canonical one-URL-per-line manifest, suitable for the original CLI's `--targets-file` argument.
- `lightup-lab-plan-receipt.json` — PRIVATE source-bound receipt with input/canonical manifest SHA-256, endpoint count, pinned original CLI/validator sources, and SHA-256 of the generated HTML/command; no endpoint values.
- `lightup-lab-plan-handoff.html` — scriptless, CSP-pinned handoff showing the exact preview command, counts and private paths; endpoint values are not embedded.
- `lightup-lab-preview-command.txt` — exact shell-quoted display-only command using `--preview-only`.
- `lightup-lab-minimal-summary.json` — separate privacy-minimal, counts-only `REVIEW_ONLY` stakeholder handoff with no endpoint literals, source paths, source hashes or identifying records; local validator checks are not permission.

The command is generated but **never executed**. A human may inspect it and, separately, run the existing CLI with `--preview-only`; that original mode validates the same input without running an assessment. The future preview output path is intentionally not created by the launchpad.

## Safety boundaries

All receipt flags remain `authorized=false`, `consent_verified=false`, `dispatch_allowed=false`, `release_allowed=false`. Source content/identity, client identity, scope approval, operator consent and HUMAN GO are each explicitly unauthenticated/false. The receipt does not authenticate source identity, client identity, scope approval or consent. No subprocess, assessment, model call, target interaction, DNS, network request, grant, scan, remediation, retest or release occurs. Original exact-head CI, source-owner/security/privacy review, authentic separate client/operator consent, action-time revocation and HUMAN GO remain mandatory.

## Offline reopen and handoff integrity

On the same verified PR checkout (and Python interpreter), re-open the generated packet without running its displayed command:

```bash
python3 assessment-launchpad/launchpad.py --verify-output-dir ~/private-lab-launchpad-output
```

Reopen demands the original five owner-owned single-link mode-0600 regular files in an owner-owned mode-0700 directory. It checks bounded stable bytes, the canonical manifest and ordinals, exact known receipt schema and literal-false authority flags, the pinned original CLI/scope sources, the stored HTML/command content hashes, and exact expected `--preview-only` command. It does not fetch outside the local workspace, run a subprocess, create an output file, authenticate the original source producer, verify client scope authority or prove that a target was assessed. The digest hashes are **unsigned consistency checks only**: an attacker controlling both payload and receipt could rewrite both. Mismatch fails closed with HOLD and no output.

The separate minimal summary is deterministically reconstructed during reopen; any extra source identifiers, paths, hashes, or edited authority statements make the bundle fail closed. It is a low-detail planning artifact, **not proof of confidentiality, anonymous identity, validated scope or assessment**. Its endpoint count may still be sensitive in a small engagement.


## PRIVATE HUMAN follow-up desk

A second source-bound offline workflow turns one completed five-file Launchpad preview packet into a PRIVATE, human-only review desk. It does not execute its preview command, authorize any asset, perform network requests, or assess any target.

Create a new, separate directory owned by the current user with mode 0700 (e.g., mkdir -m 700 ~/private-lab-human-round-1). Then run:

    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --output-dir ~/private-lab-human-round-1

The desk first reopens all five original files through the pinned original URL/isolated-lab scope validator. It creates four owner-only, no-overwrite mode-0600 files:
- lightup-lab-human-private.json: a source-byte-bound per-slot HUMAN planning worksheet. Only ordinal slots, stages, roles and up to 400-character notes may be edited. All authority, consent, dispatch and release flags remain false.
- lightup-lab-human-private.html: a CSP-pinned, scriptless printable workroom. **Contains the original endpoint URLs and private notes. Never publish or host it.**
- lightup-lab-human-counts.json: counts by fixed stage and role. Excludes endpoints, identifiers, paths, hashes and notes.
- lightup-lab-human-counts.csv: the same fixed-vocabulary counts for offline planning, no source or note values.

The initial worksheet assigns NEEDS_INPUT and UNASSIGNED to every original endpoint slot. Human stages are limited to NEEDS_INPUT, HUMAN_REVIEW and FOLLOW_UP; there is intentionally no APPROVED, CLEARED or DONE state. Neutral role choices are UNASSIGNED, LAB_OPERATOR, SCOPE_OWNER, SECURITY_REVIEWER and PRIVACY_REVIEWER.

To record a subsequent HUMAN follow-up, manually edit only the stage, role and note values in a copy of the owner-private JSON worksheet. Do not change its original source fingerprint, slot ordinals or false authority flags. Make a new empty owner-only 0700 directory and run:

    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --responses ~/private-lab-human-round-1/lightup-lab-human-private.json --output-dir ~/private-lab-human-round-2

Strict JSON duplicate-key rejection, source fingerprint binding, exact original endpoint count and ordered slots, neutral stage/role schema, and owner/mode/no-link bounded stable reads apply before publication. Existing rounds are not overwritten. To re-open a completed review round read-only, revalidate against the SAME original packet:

    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --verify-review-dir ~/private-lab-human-round-2

This checks the four output artifacts against the canonical worksheet and original-source manifest bytes; hashes here are UNSIGNED LOCAL CONSISTENCY ONLY. The aggregate handoffs are low-detail, not a promise of statistical anonymity in small engagements. HUMAN notes never become security findings, client approval, remediation proof or a scan permit. All existing source-owner, hosted/permanent named VPS CI, independent security/privacy review, distinct authenticated client/operator consent with action-time revocation, and HUMAN GO gates remain mandatory.


### Guided local HUMAN review (no JSON editing required)

Use an interactive terminal instead of manually editing the worksheet:

    mkdir -m 700 ~/private-lab-human-guided
    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --interactive --output-dir ~/private-lab-human-guided

The interactive mode shows ONLY source ordinals (never the endpoint URLs), a fixed menu for stage and reviewer role, and the length—not the content—of any previous note. Enter a free-text note through a non-echoing terminal prompt. Enter retains the current value and a single hyphen clears an old note. Nothing is stored in shell history. A refused value or interrupted session cannot publish a partial new round.

To continue an older round interactively, add the --responses argument pointing at that old round's private worksheet and choose another distinct empty output folder. All exact-source and worksheet-validation protections still apply before and after editing. The HTML and JSON artifacts remain **private unencrypted files on disk**, regardless of the non-echoing terminal input. The absence of actual authority/consent/HUMAN GO still applies.
