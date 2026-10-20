# LightUp — offline scope & revocation tabletop

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** A usable, Dutch-language, fictional operator training workspace. No grant, real client approval, live scan, detection, model access, network, tenant lookup, scanner invocation, deployment or changed LightUp authority path.

## Run

**Recommended:** open [`standalone.html`](standalone.html) directly as a local file (one portable, completely bundled HTML with exact SHA-256 CSP pins over the JS and CSS). To modify source, open `index.html` locally in a current browser with `app.js` and `style.css` in the same directory. Run `python3 build.py` to regenerate `standalone.html` deterministically from those three sources. Nothing is installed. Browser Content-Security-Policy denies network connections, frames, objects, remote fonts and external images. The app uses memory only: no cookies, storage, analytics, fetch, worker, third-party script, API or URL routing. If a browser's file-origin policy blocks the same-folder script, serve **only to yourself** from a local offline environment; do not share access or open this directory on a public interface. Do not import real operator exports.

1. Start from one of four fictional examples or compose up to 64 named events. The fixed event vocabulary has no asset/target/tenant names or free-text field.
2. Review each event's outcome and the five current fictional conditions. Press a simulated execution attempt to see whether **within this exercise only** a requirement is missing.
3. Add an expiration, withdrawal, scope or risk change, fresh scenario attestation or emergency STOP. Move individual events up/down or remove any step; the full simulated timeline is recomputed immediately. Earlier fictional attestations never silently carry across scope/risk/window changes; STOP remains active in that scenario.
4. **What-if comparison:** mark any fictional timeline as a baseline and then add, reorder or remove steps. Inspect the first diverging event, differences in toy HOLD reasons, stop, consent, scope/risk and attempted dispatch. Baseline remains in memory and can be explicitly cleared. Fictional comparison does not infer a real security verdict.\n5. Export the fixed-vocabulary JSON **v2** with optional local baseline, or Markdown with comparative HUMAN notes. Exact byte-canonical older v1 exports remain importable; only own canonical JSON is admitted and failed import cannot replace current timeline/baseline.
6. **Local workshop collection:** store up to eight separate fictional scenarios and their optional baselines into numbered local-memory slots. Load any stored scenario back into the editor with a confirmation, individually replace or remove slots, or compare any two slots side-by-side (first differing step, toy HOLD categories, consent states, revision labels, emergency STOP, and simulated dispatch attempt totals). The two selectors never contact any source or confer readiness.
7. Use **Volledige verzameling opslaan (.json)** to save editor + all eight slots to an explicitly selected local JSON file. Strict v3 own-canonical JSON import is atomic; v1/v2 single-scenario exports can still be opened and intentionally reset the collection. An asynchronous file read refuses to overwrite later changes; replacing saved slots or an existing baseline requires an explicit HUMAN confirmation. The grouped Markdown briefing includes aggregate fictional status for all eight slots.
8. **Historical attempt review:** filter the 64-event timeline by all events, fictitious dispatch attempts, dispatch attempts that encountered at least one toy HOLD, or scope/risk/consent/revocation changes. The separate retrospective view lists all prior simulated attempts with their **then-current** missing toy conditions even when subsequent toy declarations make the current scenario look complete. Both the eight-slot table and grouped Markdown distinguish current fictitious missing conditions from historical blocked attempts.
9. Print a local summary. Start a new scenario to clear an emergency STOP; this does **not** reset or change any real LightUp state.

## Product boundary

This is **not an interpreter, acceptance gate or simulator of LightUp's real policy implementation**. Every event, issuer, risk change and state transition is fictional and unauthenticated. The display text `Oefenprecondities aanwezig` means **only** that the user manually entered two toy consent events while no toy blocker remains. It does not imply real approved scope or test coverage. Report and scenario/workshop exports carry six literal false authority flags and do not contain real targets, credentials or client data by design. They are not authenticated or signed and must not be used as source evidence.

- Real separate current client/operator consent, persisted provenance, exact approved assets/capabilities, duration, risk, origin, durable revocation at the actual I/O boundary, security/privacy/browser review, canonical hosted plus permanently registered named VPS CI, and explicit HUMAN GO remain mandatory.
- Draft scope owner issues [#177](https://github.com/Zennay/Lightup/issues/177), [#182](https://github.com/Zennay/Lightup/issues/182), [#829](https://github.com/Zennay/Lightup/issues/829) and runner [#1144](https://github.com/Zennay/Lightup/issues/1144) remain unaffected.
- Standalone files are new under `scope-revocation-tabletop/`. No existing app, source-owner, scanner, grant, portal, CI, test or workflow file touched.
- No QA/regression/test suite is shipped. Syntax checks are appropriate build inspections but are not original security/permission/browser approval.

## Events

`CLIENT_CONSENT`, `OPERATOR_CONSENT`, `SCOPE_CHANGED`, `RISK_CHANGED`, `CLIENT_REVOKED`, `OPERATOR_REVOKED`, `WINDOW_EXPIRED`, `NEW_WINDOW`, `EMERGENCY_STOP`, `DISPATCH_ATTEMPT`. These terms label fake training inputs, **not actual events or durable grants**.

## Current implementation limits

No user-provided names/text in the workspace; no real timestamp, actor identity, source signatures or legal permissions; no trusted parser of outside exports. Files may still require appropriate private handling. Use the shipped one-file `standalone.html` offline artifact or the three-source-file developer build; the UI and canonical JSON are bounded and never persist automatically. This is a tabletop aid, not a production release.
