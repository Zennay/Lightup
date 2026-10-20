# LightUp — offline scope & revocation tabletop

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** A usable, Dutch-language, fictional operator training workspace. No grant, real client approval, live scan, detection, model access, network, tenant lookup, scanner invocation, deployment or changed LightUp authority path.

## Run

**Recommended:** open [`standalone.html`](standalone.html) directly as a local file (one portable, completely bundled HTML with exact SHA-256 CSP pins over the JS and CSS). To modify source, open `index.html` locally in a current browser with `app.js` and `style.css` in the same directory. Run `python3 build.py` to regenerate `standalone.html` deterministically from those three sources. Nothing is installed. Browser Content-Security-Policy denies network connections, frames, objects, remote fonts and external images. The app uses memory only: no cookies, storage, analytics, fetch, worker, third-party script, API or URL routing. If a browser's file-origin policy blocks the same-folder script, serve **only to yourself** from a local offline environment; do not share access or open this directory on a public interface. Do not import real operator exports.

1. Start from one of four fictional examples or compose up to 64 named events. The fixed event vocabulary has no asset/target/tenant names or free-text field.
2. Review each event's outcome and the five current fictional conditions. Press a simulated execution attempt to see whether **within this exercise only** a requirement is missing.
3. Add an expiration, withdrawal, scope or risk change, fresh scenario attestation or emergency STOP. Move individual events up/down or remove any step; the full simulated timeline is recomputed immediately. Earlier fictional attestations never silently carry across scope/risk/window changes; STOP remains active in that scenario.
4. Export the fixed-vocabulary JSON for private offline resume or Markdown for a HUMAN exercise conversation. Only exact byte-canonical JSON that this app emitted is admitted on import. A failed import does not replace the running scenario.
5. Print a local summary. Start a new scenario to clear an emergency STOP; this does **not** reset or change any real LightUp state.

## Product boundary

This is **not an interpreter, acceptance gate or simulator of LightUp's real policy implementation**. Every event, issuer, risk change and state transition is fictional and unauthenticated. The display text `Oefenprecondities aanwezig` means **only** that the user manually entered two toy consent events while no toy blocker remains. It does not imply real approved scope or test coverage. Report and scenario exports carry six literal false authority flags and do not contain real targets, credentials or client data by design. They are not authenticated or signed and must not be used as source evidence.

- Real separate current client/operator consent, persisted provenance, exact approved assets/capabilities, duration, risk, origin, durable revocation at the actual I/O boundary, security/privacy/browser review, canonical hosted plus permanently registered named VPS CI, and explicit HUMAN GO remain mandatory.
- Draft scope owner issues [#177](https://github.com/Zennay/Lightup/issues/177), [#182](https://github.com/Zennay/Lightup/issues/182), [#829](https://github.com/Zennay/Lightup/issues/829) and runner [#1144](https://github.com/Zennay/Lightup/issues/1144) remain unaffected.
- Standalone files are new under `scope-revocation-tabletop/`. No existing app, source-owner, scanner, grant, portal, CI, test or workflow file touched.
- No QA/regression/test suite is shipped. Syntax checks are appropriate build inspections but are not original security/permission/browser approval.

## Events

`CLIENT_CONSENT`, `OPERATOR_CONSENT`, `SCOPE_CHANGED`, `RISK_CHANGED`, `CLIENT_REVOKED`, `OPERATOR_REVOKED`, `WINDOW_EXPIRED`, `NEW_WINDOW`, `EMERGENCY_STOP`, `DISPATCH_ATTEMPT`. These terms label fake training inputs, **not actual events or durable grants**.

## Current implementation limits

No user-provided names/text in the workspace; no real timestamp, actor identity, source signatures or legal permissions; no trusted parser of outside exports. Files may still require appropriate private handling. Use the shipped one-file `standalone.html` offline artifact or the three-source-file developer build; the UI and canonical JSON are bounded and never persist automatically. This is a tabletop aid, not a production release.
