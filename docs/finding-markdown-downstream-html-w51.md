# W51 independent downstream HTML and metadata contract (#1221)

**Scope and status:** synthetic-only, DRAFT/HOLD/NO MERGE/NO DEPLOY. LightUp HQ is Incubate, M3/M7 PLAN/LAB. This opt-in test harness is a separate child of W47 draft #1220 exact immutable SHA `caf26b94f9e13e16c323897db6be4742dd787b3d`. It does **not** alter the original #894/#100/#732 owners, default `models.py`/`reporting.py`, installed web/CLI, tenant authorization, targets, or main.

## What this actually does

The W47 optional Markdown renderer escapes source fields before producing uninstalled Markdown. The missing acceptance is the **real, explicitly configured downstream Markdown→HTML engine** and its runtime flags. Upstream escaping alone does not prove HTML script, attribute, linkification or privacy safety. The new standalone W51 module provides an *opt-in* interface that invokes an explicitly supplied Markdown-to-HTML callable with a purely synthetic Finding and applies a conservative allowlist to the resulting HTML fragment.

The synthetic finding intentionally contains apparent Markdown links, JavaScript-looking schemes, raw-tag-looking text and literal math dollar delimiters, plus a private metadata canary that must never reach the Markdown or HTML. A known text-only adapter is a **positive diagnostic control**, not a real parser or proof of installed behavior. Unsafe synthetic renderers test the gate's negative controls: scripts, SVG, MathML, iframe, style, form, image, linkification, HTML comments, event/CSS/class attributes, malformed tag nesting, missing expected evidence, omitted privacy redaction, large fragments and invalid Unicode.

The conservative allowlist includes simple headings, paragraphs, lists, plain spans, emphasis, code and line breaks, but **rejects all attributes and hyperlinks**. It intentionally rejects some perfectly safe rendered Markdown variants rather than risk claiming broad renderer support. It does **not** sanitize HTML; it only refuses a fragment if it can observe a violation. Python's `html.parser` is **not a browser DOM or complete XSS verification engine**, so passing this contract is at most one provisional lab layer of actual-engine review. Browser/DOM/CSP, extension/math/linkification and tenant-privacy checks remain separate.

## Run

Pure synthetic self-tests, no non-stdlib dependencies:

```bash
PYTHONPATH=src python -m unittest -v tests.test_markdown_html_downstream_contract_w51
```

Explicitly use a **pinned installed and reviewed** adapter *only when one is actually available*:

```bash
PYTHONPATH=src python -m tests.markdown_html_downstream_contract_w51 --renderer reviewed_module:convert
```

The CLI deliberately returns **exit 2 INCONCLUSIVE** when no explicit adapter is supplied, **exit 1 REJECTED/INCONCLUSIVE** when the adapter violates the synthetic HTML contract, and **exit 0 SYNTHETIC-ONLY PASS** for accepted synthetic HTML with its SHA-256. It never silently chooses a mock or system default Markdown renderer. A passing CLI run is **not** sufficient evidence that the installed application uses that adapter; record the exact module/version, flags, ingress/portal wiring and separate auth/privacy validation before asserting any application-level claim.

## Exact-head evidence and owner gates

- Record HEAD of the add-only W51 branch and review the actual diff; no original/default/source owner files should change.
- Hosted Python 3.11 and 3.14 synthetic offline and real-producer integration tests must complete on that exact HEAD; these prove only contract regression controls.
- Registered permanent self-hosted LightUp CI on `vps-bb300bba` must complete successfully on that exact HEAD. A queued workflow is **not** proof.
- A **real, pinned production-intended** Markdown-to-HTML engine must be selected and actually exercised with its flags, verified independently against XSS, links, math, privacy, metadata and current-main compatibility. No such engine is installed/proven by these self-tests.
- Original #894/#100/#732 source owners, security/privacy and current-main integration owners must review, and explicit release authorization is required.

No clients, real assets, authorization grants, scanners, exploits, live fixes, actual retests, merges or deployments.
