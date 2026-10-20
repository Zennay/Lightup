# LightUp PRIVATE lab disclosure preflight

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Independent add-only operator companion, not a scanner, grant, source authenticator, security verdict or release.

## Actual product

preflight.py takes 1–12 already-produced owner-PRIVATE original isolated-lab JSON artifacts and calls the *original* lightup.lab_inspect.inspect_artifact() validator. Unsupported input or a missing original module produces HOLD. The companion copies only explicitly bounded, allowlisted, aggregate fields from the original inspector: no target address, original path/filename, run/scenario ID, finding title, evidence text, model response, credentials or source objects enter the outputs.

In an **existing owner-owned 0700 PRIVATE directory** it creates these files, without overwrites:

- PRIVATE-review.html: scriptless, printable PRIVATE original-declaration review with source-ordinal, counts, evidence-ref coverage and explicit HOLD/authority warning. Offline CSP denies all network connections.
- PRIVATE-receipt.json: machine-readable PRIVATE source-free per-ordinal declarations, with source_byte_bound=false, all authority flags false, no hashes or original content.
- PRIVATE-counts.csv: an independent small-cohort-suppressed count handoff. For fewer than five source files even the source count is suppressed. With larger cohorts, every nonempty artifact kind needs at least five entries or the entire kind breakdown is suppressed. This is NOT proof of anonymity; distribution remains a HUMAN decision.

Input is admitted by the original lab inspector as bounded non-symlink local JSON. Output files are exclusive 0600; ordinary writing failures clean up new outputs. Nothing uploads, executes a model, scans, grants, or contacts a network.

## Usage (offline only)

The original inspector lives on held original source-owner [PR #1610](https://github.com/Zennay/Lightup/pull/1610), reference db1b81f359a42274d7cfe00a811e9539649ded62, **not yet on main**. Use an environment where genuine reviewed original owner source is installed. The companion does not vendor or alter it. Imported code is not itself cryptographic provenance. Without it, the workflow fails closed.

~~~sh
mkdir -m 700 ./private-disclosure-desk
python3 assessment-disclosure-preflight/preflight.py \
  ./private/assessment-01.json ./private/assessment-02.json \
  --private-output-dir ./private-disclosure-desk
~~~

Exit **2 = REVIEW_ONLY** after files are privately produced. Exit **3 = HOLD** and no approval; exit 0 is never a release signal. Minimum source cohort defaults to five and can only be raised via --minimum-cohort (up to twelve).

## HUMAN disclosure checklist

Before any external handoff, check the genuine origin of each private source, current client/operator rights and action-time revocation, confidentiality/retention conditions, whether aggregated counts could re-identify a customer or laboratory, and the intended recipient. A source ordinal is *not* a durable identifier. The receipt is **not byte bound or signed**, and identical aggregates can arise from different source bytes. The PRIVATE CSV is not by definition anonymous or safe to publish. Unverified findings remain unverified.

**Release fence:** the parent LightUp project remains Incubate / M3-M7 PLAN/LAB ONLY DRAFT/HOLD. No main merge or deploy, active target, grant, deletion, retest or client authority. Original exact-head GitHub hosted and permanent named VPS CI, original source owner and independent security/privacy/browser review, #177/#182/#829, separately authenticated current client/operator permission with at-use revocation, and explicit HUMAN GO are still required. No QA suites, CI workflow, scanner, runtime, authorization or other workers' files are modified.
