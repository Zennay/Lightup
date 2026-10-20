# LightUp PRIVATE Scope Disclosure Desk

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Offline HUMAN-only helper; not an authorization product, security guarantee, or declassification.

## Use

**Fastest:** open or distribute the already generated **PRIVATE-disclosure-standalone.html**; the recipient can independently open **PRIVATE-verify-standalone.html**. Both files embed the complete CSS and JS with exact SHA-256 CSP pins, require no adjacent assets, and use no external resources. Alternatively keep index.html, desk.css, desk.js, verify.html and verify.js together in one directory.

For repeatable packaging, run the Python standard-library **package.py** with no flags to verify both committed standalone assets byte-for-byte against the original source. The optional --output-dir PATH writes exclusive private 0600 portable copies into an existing directory without overwriting existing files. This does not run QA suites. It does not require a server, network, model, account, scanner or installation.

1. Choose a HUMAN-owned PRIVATE UTF-8 TXT, CSV, JSON, MD or LOG (2 MiB maximum). Invalid UTF-8, NUL/control characters, invalid filename shapes, empty or oversized input HOLD.
2. Add 1–30 exact case-sensitive sensitive values to mask, 3–128 characters each. Each must occur in the original text. Values are not echoed in the rule list.
   Optionally select specific LOCAL categories and click **Add all selected suggestions as masks**. The human-triggered suggestion engine searches Bearer/credential/JWT/API token patterns, email addresses or HTTP(S) URLs/IPv4-like addresses, according to your choice. New exact literal matches are added atomically within the original 30-mask ceiling and never displayed in the rules list. A large, invalid or over-capacity selection HOLDs without adding partial masks. This is a convenience feature, **not** comprehensive secret detection, contextual privacy review or approval; check the entire transformed output. Multiline private-key blocks require separate source-owner removal because literal rules are single-line only.
3. Prepare a redacted preview. A single deterministic left-to-right replacement pass uses [REDACTED]. Longer overlapping mask alternatives take precedence. Output is bounded to 8 MiB.
4. Review **every** 8,000-character page. Heuristic hints may flag emails, URLs, credential assignments, private-key markers and IPv4-like addresses. No hits does **not** prove safe sharing. Residual Bearer tokens, JWT-shaped values, GitHub/API token-like values, AWS access-key identifiers, credential assignments or PRIVATE KEY markers cause a hard export HOLD: return to the mask rules until these heuristics no longer appear. Other possible sensitive patterns remain a HUMAN review warning.
5. Explicitly check two review warnings and type EXPORT REDACTED. Export is locked until all pages have been opened. Confirmation resets on changes and after any export.
6. Download the full redacted copy as .txt (even for structured originals, because substitution can break JSON/CSV syntax), or download the separate PRIVATE human counts receipt. The receipt contains redacted SHA-256, byte/replacement/mask counts, remaining heuristic counts, and six literal false authority flags. It excludes original source filename, original SHA, original text and mask values.
7. Clear application session when finished. Downloaded files remain on disk; browser/OS memory erasure is not guaranteed.

The resulting text may be used as OPTIONAL HUMAN-reviewed source for the existing separately owned PRIVATE encrypted scope courier. This tool does not read its encrypted format, execute it or certify that the redacted material is safe to disclose.

## Recipient continuity

Open **verify.html** or the completely bundled **PRIVATE-verify-standalone.html** with the received redacted .txt and its separate PRIVATE counts receipt .json. It reads both locally in memory and enforces exact bounded companion JSON serialization, schema, non-authority flags, redacted SHA-256 and byte length. After matching, it independently recomputes the *same source-code privacy hint categories* against the actual received text, compares those counts with the received receipt, and exposes the entire received text in 8,000-character, read-only pages for private human review. Remaining credential/JWT/API-token/Bearer/private-key hints yield **HOLD / CONTENT ATTENTION** even when the bytes match. Other matches yield only **MATCH / REVIEW ONLY**, not approval or authenticity. Changing either file clears the comparison and reader. A mismatched, malformed, duplicate-key, oversized or invalid UTF-8 receipt causes HOLD. This cannot detect a malicious sender who changed both files; confirm sender identity and current permission through a separately authenticated channel.

## Two-way PRIVATE HUMAN follow-up

Once recipient file equality and independent residual hint checks complete, the recipient can view the **entire** file in 8,000-character pages. Only after all pages were displayed and a new explicit HUMAN acknowledgment may the recipient export a bounded PRIVATE JSON reply. Possible credential, JWT, GitHub/API token, AWS-key, Bearer or private-key leftovers restrict the only allowed proposed outcome to **request more masking**. Otherwise the recipient can request context or return read-only notes. Notes are optional, at most 800 UTF-16 code units, and should never include secrets or private client identifiers. Every reply uses the actual redacted text SHA-256 and exact byte length, has a canonical fixed field order, and all six identity/consent/action/release booleans are literally false. The reply is **not** a cryptographic signature, authenticated sender proof, grant or client approval.

The source holder opens the original PRIVATE source, re-stages the intended masks and prepares its exact current redacted preview. Only then does the disclosure app enable **Read source-bound HUMAN feedback**: it accepts one local JSON reply at most 4 KiB, requires exact canonical serialization, source hash and size equality, known HUMAN-only outcomes, bounded notes and all false flags. Any changed source, change of selected reply during read or invalid structure HOLDs. Feedback is displayed as plain, read-only text and **never auto-applied** to masking rules, source files or authority. Source holders must establish the recipient's identity separately through a trusted channel; two matching hashes and a freely editable JSON do not prove that identity. Both source and feedback may remain sensitive; handle them as PRIVATE.

## Security and limitations

- CSP default-src none, connect-src none, no external assets; sibling local CSS/JS only. No fetch, WebSockets, cookies, localStorage, persistence, model, scanner, grants, targets, server actions or automatic writes.
- Masks are literal only. Unicode confusables, normalization, sensitive context, redacted semantics, non-text formats, encoded secrets and unknown fields can remain. The heuristic hints are non-exhaustive and may be wrong.
- The original is never overwritten. Download requires a deliberate user action. File SHA-256 proves only matching bytes, not authenticated source identity, approval, actual client/operator consent or revocation.
- Browsers and extensions on compromised machines may access locally loaded content. Use a trusted private environment, review the **entire** output, and verify the recipient separately.
- This helper never grants assessment authority, authorizes active targeting, verifies vulnerabilities, fixes findings or proves privacy clearance.

## Isolation and release fence

All implementation paths are new under scope-disclosure-preflight/; no original domain/web/tenant/scanner/CI or other-worker source is modified. LightUp Notion posture remains INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD. Existing #177, #182, #829, source-owner acceptance, independent security/privacy/browser review, exact approved-head hosted and permanent registered named VPS CI, real separately authenticated current client/operator consent with action-time revocation, and explicit HUMAN GO remain mandatory. No main merge, production deployment, scan, grant or release.
