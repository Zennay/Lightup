# LightUp Client Security Brief — private offline reporting preview

**Stage: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.** No new grant, client/operator consent, scope confirmation, revocation, vulnerability retest, execution path, production deployment or release approval.

## Open the working product

Open [index.html](./index.html) in a modern browser directly from the `client-brief/` folder, with the sibling `app.js`, `theme.css` and `remediation-engine.js` present. It has no build step, server, external libraries, CDN, runtime network connection, localStorage, persistent database, cookies or service worker. Its top-level CSP is `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'`. No target is contacted.

The page consumes only the **original previously authenticated** LightUp findings summary CSV:

```csv
finding_id,title,severity,retest_status,remediation
```

The original source exporter is [`src/lightup/finding_export_cli.py`](../src/lightup/finding_export_cli.py), not this browser interface. For an existing authorised LightUp operator and an authorised engagement, use the **existing** interactive export instructions in [casework PR #1568](https://github.com/Zennay/Lightup/pull/1568). The browser cannot check the exporting identity, consent, tenant or scope. Never use it to collect results from targets.

### What the product does

1. **Source intake** — select one exported CSV (≤ 1 MiB, ≤ 350 findings). The original `LightUpCasework.parseCSV` refuses unexpected columns, duplicates, invalid severity/retest enums and malformed CSV. A fatal UTF-8 decoder prevents silent character replacement. Optional earlier-source comparison requires an explicit external same-client/**same-engagement** acknowledgement; the CSV itself does not authenticate that assertion. Intake is atomic if either source is invalid.
2. **Executive dashboard** — show total findings, critical/high count, original source-reported regressions and untested count. Accessible severity and source status charts are derived entirely from the uploaded report, not from a new assessment or inference. “fixed” never means verified by this viewer.
3. **Historical review** — compare exact original source fields via the unmodified `LightUpCasework.compareSource` algorithm. Added/changed/absent/unchanged counts are shown without revealing finding IDs by default. **Absent is not resolved** and changed is not improvement or a retest.
4. **Human roadmap** — three configurable priority bands with calendar-day follow-up suggestions and an optional ISO date. Values are **illustrative**, never contractual SLAs, booked scans, authorisation windows or evidence that remediation occurred.
5. **Conversation stages** — one local discussion status per priority band (pending, awaiting client, awaiting operator, jointly documented), included in the preview, redacted JSON and private HTML. These are unsigned, self-reported human preparation notes, NOT consent or scope approval. Opening a different source explicitly warns that those stages will be reset.
6. **Client handoff** — generate a self-contained, *script-free* static HTML brief or aggregate-only JSON counters with all ten consent/grant/execution/release flags explicitly false. Default HTML contains no source finding IDs, titles, remediations, hostnames or customer notes. Titles/remediation can be deliberately included for **private authorised recipients only** with an explicit second confirmation and a warning. The private viewer also has a print layout. Human review and secure transfer remain the operator's responsibility.
7. **Forget** — clears all source data and DOM rows held by this tab. **Downloaded files remain on disk** and must be deleted separately. No automatic persistence or hidden upload is performed.

### Source pin

`client-brief/remediation-engine.js` is an **unchanged** copy of [source-owner PR #1568](https://github.com/Zennay/Lightup/pull/1568), exact pinned owner commit `9c73e8468ce271bf8c6bef4cac071e5ad9c1806b`, original path `casework/remediation-engine.js`. Both original and copied file have SHA-256:

```
c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225
```

This is a reproducible source fingerprint, **not a cryptographic authority statement** or consent evidence. The source owner branch remains untouched. New project code is limited to the separate `client-brief/` directory; this feature has no import or write access to the source code's grant, domain, webapp, activation, scanner, CI or server paths.

### Security / release posture

All source content is untrusted unless independently authenticated using the original service. The CSV source can contain client finding descriptions and identifiers even though the raw export omits target addresses and evidence; therefore work locally, do not post these CSVs or detailed briefs in issue comments and never treat a portable HTML or SHA-256 as signed evidence. A browser may not provide `crypto.subtle` for some file contexts: the UI then marks hashes unavailable rather than faking them. The redacted aggregate JSON intentionally includes source digests when available, which can be correlatable; check before forwarding.

The original mandatory exact-head hosted and permanently registered named-VPS CI, independent security/privacy review, real dual-party authenticated and revocable-at-use consent, #177/#182/#829 source-owner integration and explicit **HUMAN GO** remain unmet. **Do not merge to main, deploy, scan, dispatch, create grants or infer release permission from this separate draft.** This PR is a preview-only deliverable; nothing expands runtime authority.

## Direct inspection without QA suites

`node --check client-brief/app.js` and `node --check client-brief/remediation-engine.js` are syntax checks only, not validation of source trust or production readiness. No QA, regression or test suite was added or run for this feature.
