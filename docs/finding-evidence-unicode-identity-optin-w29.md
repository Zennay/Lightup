# W29 — optional Unicode identity admission for persisted evidence refs

**DRAFT / HOLD / PLAN-LAB ONLY — NO MERGE / NO DEPLOY.** Parent is immutable W27 [PR #1205](https://github.com/Zennay/Lightup/pull/1205), exact `014952a9745f3936379327bd9ba3c09eaccaa1d6`. W29 only adds a separate uninstalled reference module and regression tests; it does **not** change `DomainStore`, existing W27, client/tenant authorization, default reports, external scanners or `main`.

## Why

W27 checks the historical `evidence_ids_json` storage shape, exact string types, duplicate original strings, size limits and JSON decoding failures. It does not distinguish visual control/format marks or references that collapse to the same NFKC identity. Synthetic examples: `"ref:K"` vs `"ref:K"`, `"ref:visible"` vs `"ref:\u200bvisible"` and bidi-isolate characters within one stored finding. These are **potential identity/presentation ambiguities**, not demonstrated cross-tenant authorization failures, spreadsheet exploits, or incidents.

## Optional contract

`decode_finding_evidence_unicode_identity_checked(raw)` first invokes the W27 strict JSON decoder; then rejects Unicode category `C*` characters (including controls, format, surrogate/private/unassigned), non-ASCII separators, and leading combining marks without a visible base. It rejects NFKC-equivalent references **within a single finding's ordered list**, including compatibility characters. It returns references **without normalization or mutation**, preserving valid CJK, accented strings, base+combining mark and emoji+variation selector.

This is intentionally conservative and may reject genuine historic IDs. Identity checking is only local to one record: **it neither validates an evidence object exists nor proves evidence provenance, tenant ownership, redaction or remediation/retest authorization.** NFKC does not solve general Unicode confusables. W27's provisional 262 KiB / 128 refs / 4 KiB limits still apply.

## Synthetic acceptance

`tests/test_finding_evidence_unicode_identity_optin_w29.py` uses a disposable `DomainStore` SQLite finding, including real persisted `evidence_ids_json` field reads, and compares W27 acceptance vs W29 denial. It covers ordered international positives, empty manual evidence, format/bidi and ASCII controls, lone-surrogate W27 baseline rejection, separators, leading marks, within-row NFKC collisions, late-list failure and **original SQLite bytes unchanged**. No real clients, targets, credentials or external connections.

Review/run on branch exact HEAD:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_evidence_unicode_identity_optin_w29.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

**Acceptance gates:** original #828/#856/#886 read owner inventories historic reference encodings and approves the *stricter* compatibility policy; independent privacy/security review, cross-Python reproducible unit/integration tests, current-main composition and the registered self-hosted `[self-hosted,zcloud,vps]` permanent LightUp CI on **exact HEAD** must complete before any adoption. The default `DomainStore._finding_from_row()` is **still unchecked**, the helper is not installed or invoked by canonical tenant selectors and there is no confirmed evidence verification. Do not merge/release/deploy until owners explicitly approve.
