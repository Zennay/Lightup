# W25 — synthetic session-cookie privacy boundary (expected RED)

Status: **BRANCH ONLY / EXPECTED RED / PLAN-LAB / HOLD / NO MERGE / NO DEPLOY**.

This independent tests/docs child is stacked on the green W23 opt-in checked
WSGI CSV proof `44a390dac06199f68faee858a5bc040e9b9d0878`.
It does not modify inherited source, the shared redactor, default CLI/web,
DomainStore, canonical `main`, scanner, target, or installed ingress.

## Privacy observation and invariant

The legacy `redact_text` lists bounded credential labels
(`authorization: bearer`, AWS access key, `api_key`, `token`, `secret`,
`password`), but not the named `lightup_session` browser cookie. The
opt-in checked WSGI exporter validates Unicode/formula integrity and
redacts those known patterns before rendering, but **does not certify arbitrary
free-text as secret-free**. Synthetic `Set-Cookie: lightup_session=...`
text in a finding title or remediation can therefore survive into a
tenant-authorized CSV download. This is a **lab presentation/privacy seam**,
not evidence of customer exposure or an exploit.

## Test-only acceptance for privacy owner

`tests/test_finding_export_checked_wsgi_cookie_privacy_w25.py` uses actual
in-process authenticated WSGI and disposable SQLite, with two synthetic
exported free-text placements. A positive control still expects the existing
`password=...` redaction and unchanged finding rows.

The **negative expected-RED** contract is deliberately implementation-neutral:
the known synthetic session value must not appear in the response. An owner
may choose an atomic generic 400 denial or a carefully reviewed redaction that
retains CSV 200, but must not pass through the cookie value. Whole-batch
privacy/secret-classification, acceptable patterns, leakage of unknown secrets
and human review are **outstanding**, not solved by this isolated canary.

Reproduction on a trusted offline runner:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_export_checked_wsgi_cookie_privacy_w25.py' -v
```

Expected RED has **not been independently executed/verified** for this
branch. Do not count it as a source fix, CI acceptance or live incident;
there is no new PR or extra CI dispatch while the registered self-hosted
queue is occupied.

## Required handoff

Original CSV/redaction source owners, independent privacy/security review,
evidence-free-text classification, tenant/session/ingress gates, safe
latest-main integration, exact-head hosted + **permanent VPS CI**, and
release approval. **No live clients, credentials, targets, scanning,
authorization grants, executed remediation/retests, merge or deploy.**
