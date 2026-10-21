# LightUp · Isolated-lab batch launchpad

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** New-only `assessment-launchpad/` product pinned to original held CLI source commit `74e865201c8a4270e404046ef3447eb7f190edfb`. The original source owner, CLI, `_admit_explicit_lab_url`, `LabScenario`, and `ScopePolicy` files are not modified.

## Browser composer

Open `composer.html` locally. It is one standalone file with a strict hash-pinned CSP (no unsafe-inline script/style) and no external assets, APIs, storage, DNS or network access. Compose 1–16 distinct literal HTTP(S) URLs within the native CLI\'s 16 KiB manifest limit, or import a private existing local manifest. Import is all-or-nothing (strict UTF-8, no BOM/NUL, no duplicate values); failed imports retain the current editor. Edit/remove/reorder endpoint slots before clicking **Download private text manifest**. Nothing is uploaded or saved to browser storage. Browser checks are convenience-only and do not prove an endpoint is isolated.

Browser downloads cannot set file permissions. Before using the native CLI, move the downloaded file to a private directory and set mode `0600`.

## Native validator-backed handoff

Requires the repository checkout at the pinned source commit and the existing project Python dependencies. Create an owner-only output directory separate from the manifest directory:

```bash
chmod 600 ~/Downloads/lightup-lab-targets.txt
mkdir -m 700 ~/private-lab-launchpad-output
python3 assessment-launchpad/launchpad.py \
  --manifest ~/Downloads/lightup-lab-targets.txt \
  --output-dir ~/private-lab-launchpad-output
```

The CLI checks the Git blob hashes of the pinned original `labrun.py`, `labeval.py`, `scope.py` and `models.py` before loading the original `_admit_explicit_lab_url` and `LabScenario`. `LabScenario` invokes the original isolated loopback/private-lab `ScopePolicy`. No DNS resolution or target connection is made.

The command requires an owner-owned input regular file with mode `0600`, no symlink/hard-link alias, bounded stable contents (16 KiB), and 1–16 distinct endpoints. The output directory must already exist, be owned by the current user and have mode `0700`. Outputs are exclusive no-overwrite files with mode `0600`; failed bundle publication removes newly created outputs.

The output directory receives four private artifacts:

- `lightup-lab-targets.txt` — canonical one-URL-per-line manifest, suitable for the original CLI's `--targets-file` argument.
- `lightup-lab-plan-receipt.json` — source-bound anonymous receipt with input/canonical manifest SHA-256, endpoint count and source validator pin; no endpoint values.
- `lightup-lab-plan-handoff.html` — scriptless, CSP-pinned handoff showing the exact preview command, counts and private paths; endpoint values are not embedded.
- `lightup-lab-preview-command.txt` — exact shell-quoted display-only command using `--preview-only`.

The command is generated but **never executed**. A human may inspect it and, separately, run the existing CLI with `--preview-only`; that original mode validates the same input without running an assessment. The future preview output path is intentionally not created by the launchpad.

## Safety boundaries

All receipt flags remain `authorized=false`, `consent_verified=false`, `dispatch_allowed=false`, `release_allowed=false`. Source content/identity, client identity, scope approval, operator consent and HUMAN GO are each explicitly unauthenticated/false. The receipt does not authenticate source identity, client identity, scope approval or consent. No subprocess, assessment, model call, target interaction, DNS, network request, grant, scan, remediation, retest or release occurs. Original exact-head CI, source-owner/security/privacy review, authentic separate client/operator consent, action-time revocation and HUMAN GO remain mandatory.
