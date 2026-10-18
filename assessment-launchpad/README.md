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
