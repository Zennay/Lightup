# LightUp Scope Intake Matrix — HUMAN preparation only

A complete, private, networkless operator workroom for proposing assessment boundaries and comparing revisions before the original authenticated LightUp scope/consent workflow. The local UI is in **index.html** and **app.js**.

## Open

Save both files into the same local folder and open index.html in a modern desktop browser. The page loads no external resources and does not call endpoints, create grants, scan, evaluate findings, open a provider, or store records in localStorage/cookies/IndexedDB. The HTML uses a strict no-network CSP and a local script. Prefer standalone.html, a self-contained, one-file offline app with SHA-256 CSP-pinned production JavaScript. Rebuild after source changes with python3 scope-intake-matrix/build_standalone.py. No server is needed. Do not enter secrets, API keys, customer login details or active-target credentials.

## Product flow

1. Name the internal draft, enter a self-declared, unverified client label and human reviewer alias, requested local start/end times, proposed descriptive ceiling and human review questions.
2. Add 1–32 literal host / IPv4 / narrow canonical CIDR entries. Mark each as a proposed inclusion or explicit exclusion. For included entries choose a proposed passive inventory, HTTP, TLS or isolated-lab review capability. Mark ownership evidence as unverified, claimed (unverified), or documents requested. Track draft, needs-client-review, or blocked with a private question per row.
3. Inspect live completeness warnings. Export a PRIVATE plain JSON proposal only once schema, uniqueness, date, string and exclusion-capability checks pass. Export requires a separate local privacy acknowledgement. All five authority booleans are literally false.
4. Later open the exact app-generated private JSON locally. The imported file must be <=64 KiB, strictly canonical JSON, exact schema and key order with no duplicate keys, all required fields and bounded nested records. Malformed or altered imports fail atomically without replacing the in-memory draft.
5. Compare the current draft against a separately opened older valid app-generated draft: explicit added, removed and field-changed literal proposals. These are not approved scope changes or proved revocations.
6. A built-in HUMAN follow-up agenda derives a private task list from requested capabilities, ownership proof gaps, exclusions, blockers, questions and risk. An additional SCRIPTLESS PRIVATE HTML download is source-escaped, CSP-protected and capped at 64 KiB; human approval remains external.
7. Optionally export a separate aggregate-only counts file (with a human acknowledgement for possible small-cohort disclosure) or print a PRIVATE human brief. The aggregate omits client/asset labels and free text.
8. Clear the page's in-memory draft explicitly. Reloading also discards unsaved data. The page never automatically saves or sends it.

## Trust boundary

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** The UI is deliberately not connected to any source-owned domain authorization logic, request registry, persisted grants, approval workflow, action-time revocation, execution permit, worker or scanner. A checked-off input is self-declared content, not independent customer or operator authentication, ownership proof, security review, revocation, evidence, risk approval or HUMAN GO.

- PREPARATION_ONLY is never AUTHORIZED or PASS.
- Added entries are not granted; excluded/removed entries are not evidence of actual revocation.
- A locally complete plan may still be entirely unauthorized or outside approved risk.
- Local time inputs are planning hints, not authenticated timestamps.
- Receipts and JSON exports are unsigned. PRIVATE downloads are unencrypted; authorized secure delivery is outside this tool.
- No broad/wildcard asset input is accepted: explicit lowercase DNS names, canonical IPv4, /24–/32 canonical IPv4 networks only, with no path/port/scheme.
- An alleged ownership claim remains unverified even when a human marks it as claimed.

Release into main, production deployment or action against real customer targets remain on HOLD. Existing exact-head GitHub-hosted and permanently registered named VPS CI, original source-owner acceptance, independent security/privacy/browser review, original #177/#182/#829, separately authenticated current client/operator consent and action-time revocation, and explicit HUMAN GO remain necessary. No part of this draft package alters those gates.

## Implementation ownership

New-only paths under scope-intake-matrix/ on independent branch chatgpt/lightup-scope-intake-matrix-20261020-gpt6. Original LightUp domain, auth, web, registry, scanner, queues, source-owner paths, QA/tests, CI/runner workflows and active worker branches remain unchanged.

## Product integrity

The import function deliberately accepts only the exact pretty-printed UTF-8 JSON representation produced by this app. This excludes duplicate JSON keys and other alternate spellings without parsing ambiguous JSON into trusted state. Text values reject invisible format/control categories; every downloaded artifact uses a bounded, explicit operator click. The offline interface uses DOM text/value assignment for entered fields; it never injects those fields into HTML markup.

Only production JS parse / artifact construction and direct read-only inspection are intended in this implementation; no QA, regression or test suites are added or executed under the 17 October 2026 instruction.
