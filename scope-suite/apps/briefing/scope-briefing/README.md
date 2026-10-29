# LightUp Scope Briefing — private local conversation tool

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is a separate, read-only human conversation aid, **not** authenticated consent, asset ownership, a formal request, a risk approval, a grant, a revocation mechanism, a permit, a runtime execution policy, or a release gate. It cannot run assessments.

## Open locally
- Use `scope-briefing/index.html` beside its `style.css` and `app.js`; or use the produced self-contained `scope-briefing/standalone.html`.
- All files operate without a web server. Restrictive CSP denies connections, images, forms, plugins and outbound content. No cookies, browser storage, accounts, third-party libraries, fonts, telemetry, local DB or API access.
- Select an **original** Scope Planning Studio v1 JSON export, 1–65536 UTF-8 bytes. Import is atomic: on invalid input the previously displayed document stays untouched. A newly admitted source clears earlier temporary checkbox selections and hides exact asset strings.
- Expand exact assets only while physically reviewing the screen. The page re-hides them on print or tab visibility loss. Use **Forget** to clear all original source data from the current page; closing the tab also discards in-memory state. This does not securely erase copies outside the browser.
- Review counts, literal repeated items, exact include/exclude text overlap, three proposed activity booleans, risk 1–4 and whether local planning is present. The app does not normalize or resolve IPs, DNS, CIDRs, window offsets, issuer identities or scope ownership. A syntactically readable draft is not a valid executable target.
- When an original concept is already open, choosing a **byte-different second draft** stages a candidate rather than silently overwriting the first. Both original-byte SHA-256 prefixes and anonymous *literal* counts of included/excluded strings added/removed, risk/mode/activity and local-window change indicators appear on screen. The original proposal and human discussion remain intact until a separately confirmed **Use new version** action. Discard or choosing the same byte-identical file preserves current work; applying resets all question checkboxes. These comparisons cannot establish equivalent CIDR coverage, DNS aliasing, tenant ownership or signed revision identity.
- The discussion checkboxes are ephemeral. They are never exported as proof, authorized, approved or verified.
- Download the **anonymized review JSON** or print the always-redacted discussion card. Neither contains raw asset identities, customer labels, uploaded filenames, free text, passwords or contact details. A SHA-256 fingerprint is **not** a signature and may still allow correlation across recipients; share review exports only with intended reviewers.
- The printable briefing deliberately omits exact asset names even when the on-screen disclosure toggle is open. Use separate authenticated channels to discuss the original scope data with appropriate parties.

## Strict admission
The source must be `kind: lightup.scope_proposal_draft`, `schema_version: 1`, `state: DRAFT_ONLY`, include arrays of strings `requested_assets` and `excluded_assets`, mode `analysis_only` or `authorized_assessment`, integer risk 1–4, `proposed_activities` with exactly `passive_analysis`, `configuration_review`, `private_lab_network_checks` as literal booleans, and a `proposed_window_local` null/object field. All of `authorization`, `client_consent`, `operator_consent`, `grant`, `execution`, `revocation_checked` must be literal `false`. JSON duplicate keys (including nested) are refused with a bounded parser. Imports also reject overlong lists, untrusted control characters and malformed UTF-8. The exact original bytes are hashed with browser WebCrypto SHA-256. If SHA-256 is unavailable, admission holds closed.

## Why this exists
The authoring Studio and the separately owned handoff, permission, scheduling and withdrawal apps manage draft preparation and transfer. This **independent** discussion view is purpose-built for screen sharing or in-person client/operator scope clarification: source details remain hidden by default, review risk notices are visible without revealing asset names, and anonymous briefing export cannot accidentally become an approval record.

There is no write/API integration with any existing product owner branch. Files are exclusively within new `scope-briefing/` paths. It is not a substitute for the separately authenticated request and operator grant flow, at-use revocation, tenant isolation, source-owner integration (#177/#182/#829), independent privacy/security review, original required hosted and permanently registered named-VPS CI or explicit HUMAN GO.

No QA, regression or test suite was added to this package. The simple standalone build only copies source bytes into an HTML file and pins inline script/style SHA-256 hashes; generated output is not an independent authorization or security certificate.

## Offline packaging
`python3 scope-briefing/build_standalone.py` produces `scope-briefing/standalone.html` using only the Python standard library. It inlines the owned CSS and JS, computes their CSP hash pins, and keeps all network routes disabled. The generated file is a portable standalone browsing artifact, not a deployed portal.
