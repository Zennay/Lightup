# LightUp · Offline Lab Launchpad (assessment-runtime)

**Stage: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**

This new, independently owned module prepares **existing** LightUp lab-only CLI input. It does not scan, authenticate, grant permission, execute a target, open a socket, resolve DNS, run a model or change the original CLI source. Related original active source owner: [#1608 / PR #1610](https://github.com/Zennay/Lightup/pull/1610). Source pinned to original held commit `74e865201c8a4270e404046ef3447eb7f190edfb`; this add-only feature is proposed separately as [#1633](https://github.com/Zennay/Lightup/issues/1633).

## Two usable offline workflows

### Browser authoring (convenience; no trusted admission)

Open the [ready-to-open portable standalone Launchpad](./standalone.html) locally without supporting files. Alternatively open `assessment-launchpad/index.html` with adjacent `style.css` and `app.js`, or run the local **build-only** command `python3 assessment-launchpad/bundle.py --output NEW-private-composer.html` to publish a standalone, script-pinned local editor. It refuses to overwrite an existing file. No server, browser storage, analytics, external assets or network activity is used.

Enter distinct literal isolated lab HTTP(S) URLs, reorder or remove them, or **atomically import an existing bounded original-format private text manifest**. Import replaces all local entries only if every proposed line is valid; otherwise it keeps the previous in-memory batch. Then download a **private** UTF-8 `targets.txt` containing one URL per line. The separate optional `anonymous-plan.json` carries only counts and literal-false authority fields, with no original endpoints, hashes or scenarios. Browser checks are **advisory only**: they cover canonical IPv4 private/loopback and a conservative subset of IPv6 private/loopback literals. The actual original Python CLI decides whether to admit a target at use time.

### Native exact-source admission + four private artifacts

From a checkout with the **held original** Python package importable:

```sh
PYTHONPATH=src python3 assessment-launchpad/build.py \
  --target http://127.0.0.1:18080/ \
  --target http://10.0.0.5:8080/ \
  --output-dir ./MY-NEW-PRIVATE-LAB-LAUNCHPAD
```

Or use the browser-exported local file:

```sh
PYTHONPATH=src python3 assessment-launchpad/build.py \
  --targets-file ./targets.txt \
  --output-dir ./MY-NEW-PRIVATE-LAB-LAUNCHPAD
```

The native preparer calls **original** `_admit_explicit_lab_url` and **original** `LabScenario` scope admission, in addition to requiring literal canonical numeric IP addresses, before creating anything. Input sources are bounded ordinary no-follow files, maximum 16 endpoints. It creates the new directory exclusively in mode 0700 and its four local files exclusively in mode 0600 (no overwrites; no symlinks, fsync for all files):

- `targets.txt` — original-CLI-compatible ordered source manifest. **Private**: contains all literal lab endpoints.
- `private-launchpad.html` — **scriptless** local human briefing showing ordinal slots, original lab URLs, proposed *display-only* preview command and unsigned input SHA-256.
- `private-plan.json` — original manifest hash and count, literal false security authority flags. **Private**, despite lacking URLs.
- `START-HERE.txt` — operator guidance including the pre-existing no-work preview invocation.

A successful **preparation** exits **2** (review-only, never 0). An invalid source/destination exits **3** (HOLD), does not publish an incomplete successful packet, and does not echo rejected URLs or credentials. No fake permission, agent execution or original scenario validation result is manufactured.

## Optional original CLI preview — never executed here

After a separate, actual human check of environment, owner and explicit authorization gates, the **existing** held CLI *could* be invoked from the new local packet directory:

```sh
lightup lab-assess --targets-file ./targets.txt --preview-only
```

This is command **text**, not a scheduled action and not an instruction that bypasses source authorization. The Launchpad does not invoke it. The same manifest can be reviewed by a human alongside the original Studio draft; it does not automatically infer correspondence or grounded truth. No target URL may be taken as authenticated from a downloaded/browser-edited manifest. Only independently authenticated client/operator approval, action-time revocation checks and the original scope/target policy can govern any future action.

## Ownership and release fences

All added files live under **new** `assessment-launchpad/`. No edits to original source owner, other worker branches, scanner, auth, grant, policy, CI, workflows or tests. New PR stays **draft** and is not a release. No QA/test suite was written or run.

Before any main merge, deployment, real target assessment or approval: original exact-head hosted **and permanent named VPS CI** must pass; original source-owner acceptance and independent privacy/security review must finish; original #177/#182/#829 and real independent authenticated client/operator permission with action-time revocation and explicit **HUMAN GO** remain necessary. A lab preview, SHA-256, anonymous aggregate, source URL or this planner never proves those conditions.

## Standalone portable editor (repository artifact)

The committed `standalone.html` is already bundled from the exact new browser source and includes both CSS and JavaScript inline, constrained by exact SHA-256 CSP pins. It works as a local single-file editor and supports source-private file import/export without a web server. If changing `index.html`, `style.css` or `app.js`, rebuild the portable file with `bundle.py` before sending it to an operator: a stale source/CSP bundle is not equivalent to the current editor. The browser does not emit an original-authority approval.

## Studio source binding — original scenario-to-exact-IP handoff

The new Lab Launchpad composes the existing [Lab Scenario Studio](https://github.com/Zennay/Lightup/pull/1595) with the existing [lab-assess CLI](https://github.com/Zennay/Lightup/pull/1610) **without taking over either original owner**. The whole workflow remains offline and does not execute lab assessments:

1. In `standalone.html`, prepare exact numeric HTTP(S) lab endpoints with explicit ports. Choose an existing original **PRIVATE Studio v1** JSON source from the Studio app, select one scenario, and review the advisory declared-IP membership. The Studio source is read into local browser memory only, and no origin network calls are made.
2. Optionally choose the explicit human-selected HTTP(S) scheme and exact port and click **Prepare URL batch from selected original lab IPs**. It only drafts the full local URL list; if a prior list exists the operator must confirm replacing it. No service discovery, inferred port, scan, model or permission is invoked.\n3. When the original selected scenario's IP set matches the independently entered URL host set *with no duplicates*, download BOTH `targets.txt` and **exact original bytes** as `studio-catalog.json`. If the local endpoints later change, the Studio download is disabled until the mapping matches again.
4. Use the native, **original-validator-backed** private packet builder from the repository, e.g.:

```sh
PYTHONPATH=src python3 assessment-launchpad/build.py \
  --targets-file ./targets.txt \
  --catalog-file ./studio-catalog.json \
  --scenario-id my-isolated-lab-scenario \
  --output-dir ./NEW-PRIVATE-LAB-SCENARIO-HANDOFF
```

Only the original `lightup.lab_catalog.read_selected_lab_design` and original `LabScenario` policy are binding. The native producer rejects duplicated/malformed scenario JSON keys using the ORIGINAL Studio validator; reads and pins the exact original source's SHA-256; checks the unchanged original whole-scenario schema and every target; enforces explicit port plus exact **unique** normalized private-IP membership; and creates a private 0700 folder with private 0600 `targets.txt`, `studio-catalog.json`, scriptless `private-launchpad.html`, `private-plan.json`, and `START-HERE.txt`. Any original byte drift before the native handoff produces HOLD, no partial directory.

The generated operator command text includes `--catalog-file ./studio-catalog.json --scenario-id ... --preview-only`. **It is never executed by this module.** An offline catalog contains unsigned, self-declared scenarios and possibly declared expected findings; these are NOT factual planted ground truth, client permission, verified assessment, evidence, authority, or a scanner instruction. Browser `JSON.parse` is *not* a duplicate-key validator; native original schema admission is explicitly mandatory. Source revision changes require a fresh human binding, not silent notes carryover.

## Source-bound private packet reopen after handoff

The native packet builder now places an **artifact_sha256** map in the final `private-plan.json`, binding every original private file's bytes (including Studio catalog when present) without storing client identities, authority or secrets in aggregate output. These digests are **unsigned** and cannot authenticate a producer or proof of client permission.

After an operator transfers a prepared packet through a separately approved private channel, they can reopen the original source-bounded handoff without executing a scanner:

```sh
PYTHONPATH=src python3 assessment-launchpad/reopen.py \
  --packet ./NEW-PRIVATE-LAB-SCENARIO-HANDOFF
```

`reopen.py` opens only an existing owner-private ordinary directory (0700) and its exact original owner-private ordinary files (0600), refusing symlink entrypoints, missing/extra files, changed bytes or partial manifests. It checks the pinned original manifest bytes, reuses the unchanged original lab-scope admission, verifies exact total/unique endpoints and, for a Studio packet, revalidates the original Studio v1 source using the unchanged native source owner and the exact explicit-IP membership. It reports **only anonymous endpoint count + presence/absence of a Studio draft**, never paths, IPs, scenarios or credentials. Return code 2 means unsigned source revision is internally consistent **for human REVIEW_ONLY**; 3 is HOLD. Neither is an authorization/consent result.

Reopening an old private packet does **not** make previously permitted endpoints currently safe to run. Any subsequent activity must independently recheck original scope, authenticated client/operator consent, revocation-at-use and required release gates. A copied, replaced or missing source cannot be interpreted as remediated or approved.

## Compare two owner-private original launch proposals (source revision desk)

Two *separately prepared* `build.py` packets can now be examined as a **human proposal revision**, without contacting targets, interpreting absent endpoints as fixed, or silently mixing sources:

```sh
PYTHONPATH=src python3 assessment-launchpad/compare.py \
  --before ./PRIVATE-LAB-PACKET-OLD \
  --after ./PRIVATE-LAB-PACKET-NEW \
  --output-dir ./NEW-PRIVATE-LAB-REVISION
```

The new `compare.py` first reopens each entire private packet through `reopen.py`: original source fingerprint, 0700 directory / 0600 no-follow file checks, original lab-policy admission, strict Studio validation if present and full original hash map. It then compares **exact original user-entered URL strings only**: added proposals, proposals absent in the later selected packet and unchanged proposals. The before/after labels are *user-selected*, not a trusted sequence, audit timeline or same-customer identity proof.

The output is a new exclusive 0700 private directory with four owner-only 0600 files: a portable **scriptless human change brief** (full private URLs), a confidential original-source-fingerprint-bound JSON diff, an identity-free count-only JSON, and a START-HERE privacy/review note. This is useful for private handoff between lab operators, not a source verification of remediation. There is no implicit network, grant, runtime, CI, approval or deployment. A missing proposed URL is explicitly **not** verified remediation, revocation, client permission withdrawal, closure or a safety clearance. The new source/revision artifacts exit only 2 for human review or 3 HOLD, never authorization exit 0.
