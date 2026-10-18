# LightUp Remediation Funding Studio

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.**

This independent offline product consumes only the existing **aggregate exported planning summary** from [LightUp Remediation Capacity Studio PR #1583](https://github.com/Zennay/Lightup/pull/1583). It never imports raw finding IDs, remediation descriptions, customer identities, IPs, URLs, assets, grants, evidence, credentials, or privileged operator records. It never interacts with a target, and does not issue consent or authorisation.

## Open and use

**Recommended:** open `remediation-funding/standalone.html` locally in a modern browser. The entire product is one HTML file with SHA-256 CSP-pinned inline scripts/styles; no external dependencies, network, cookies, browser storage, accounts or server.

To prepare its input, use the original Capacity Studio's user-initiated **Export aggregate JSON** action after independently obtaining an originally authorised findings export. It produces `lightup.remediation_capacity_draft.v1`, with aggregate severity bands, weeks, available and allocated hours and the nine literal false authority flags.

1. Select that saved JSON in this app; the maximum is **64 KiB**. It rejects duplicate JSON keys, including encoded aliases; excessive nesting, non-UTF-8 input, unknown/missing aggregate fields, implausible sizes, false authority flags, mismatched severity/source totals and inconsistent per-week figures.
2. Set your own reporting currency (EUR, GBP or USD, **no currency conversion**), internal and external hypothetical hourly costs, external share, contingency percentage, one-time setup cost and an available funding ceiling.
3. Generate a **financial discussion proposal** with an estimated planned-hours cost, proposed funding gap/surplus, unplanned-capacity opportunity cost and per-week proposed costs and provisional fundable hours. The numerical settings are examples, not existing purchase agreements, approved labour rates, invoices or actual money spent.
4. Compare another hypothetical external share without mutating the source or baseline; the weekly rate model remains explicit.
5. Inspect the separate **critical/high funding exposure range** by week. Because the source export contains aggregate severity hours but no trusted per-finding spending order, the studio reports a conservative lower and upper bound on urgently needed hours that may be unfunded. Unallocated source backlog is shown separately, without assuming it has been fixed.
6. Intentionally and privately export aggregate forecast JSON (including the risk exposure bounds), a spreadsheet-safe weekly CSV or an offline printable brief. Exporting requires user confirmation. No raw finding identity is available to these exports.

## Funding model and limitations

Blended hourly rate = internal_rate × (100 − external_pct)/100 + external_rate × external_pct/100. Proposed weekly labour = planned_h × blended_rate × (1 + contingency_pct/100). One-time setup is charged to the first modelled week. Available funds are provisionally applied in week order, with first-week setup accounted for before labour. The funded-hours figure is **an upper-bound financial illustration**, not an assignment, completed repair or verified milestone. An unfunded hour is not a skipped, waived, solved, or authorised assessment.

For each week, the upper bound of nominally funded critical/high hours is min(urgent hours, funded hours), and the lower bound is max(0, funded hours − nonurgent hours). Their complements indicate the minimum/maximum potential urgent funding exposure; these are **numerical bounds only**, not case-level prioritisation or actual paid work. Rounding is to one decimal hour for display.

The source Capacity Studio's remaining backlog hours are **not** silently presented as completed or included in already allocated work. Their estimated additional cost is displayed separately, excluding future fixed setup. This estimator is intentionally simple: it does not account for taxes, contracts, overtime, salary law, skill premiums, financing, fixed recurring subscriptions or currency FX. No claim of accuracy beyond the declared hypothetical assumptions is made.

## Security and scope boundaries

- Source input schema must be the original unsigned review-only aggregate export. Its claimed "review only" controls do **not** authenticate the real client/engagement, source bytes or current consent. Only its totals are used as untrusted planning numbers.
- No cloud sync, remote resources, fetch/XHR/WebSocket, browser persistence, API call, scanning, active target, grant, remediation dispatch, retest, approval or release action.
- Dedicated additive `remediation-funding/` files only; no writes to PR #1583, original Casework PR #1568, Scope Studio, DomainStore, grants, webapp, authentication, runners, workflows or CI.
- Existing **exact-head hosted CI and permanently named VPS CI, independent security/privacy review, original scope authorisation source integration, independently authenticated real client/operator consent, at-use revocation and explicit HUMAN GO** are still required before any merge or deployment. No production merge/deploy under DRAFT/HOLD.

The generated HTML fingerprint is a reproducibility aid, *not* a signature, proof of permission, or security approval.
