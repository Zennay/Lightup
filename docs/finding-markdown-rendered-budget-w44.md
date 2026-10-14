# W44 — opt-in evidence Markdown rendered-byte budget

**M3/M7 PLAN/LAB ONLY; DRAFT/HOLD/NO MERGE/NO DEPLOY.** Independent narrow follow-up stacked on immutable W43 [DRAFT #1216](https://github.com/Zennay/Lightup/pull/1216) exact `634bbaa64e0e81f06b07ed0e5da9b9a03eb9d304`. Original `models.py`, `reporting.py`, DomainStore, authentication, installed web/CLI, background jobs, `main` and other workers' files remain untouched. Only the already-optional W31 Markdown source is modified.

## Real bound mismatch

The opt-in W31 renderer constrains raw fields to 16 KiB each and the total source payload to 1 MiB; however its HTML entity encoder can expand each ASCII quotation mark to six UTF-8 bytes (`&quot;`). Therefore the **rendered output can be several times larger than the admitted input**, and no final response-size cap was present. This is an output-resource budget mismatch in an uninstalled helper, **not proof of remote exploitation or a client incident**.

## Material correction

- New provisional **2,097,152-byte (2 MiB) rendered UTF-8 output ceiling**.
- After all records have passed preflight and been escaped into an internal list of lines, count actual UTF-8 bytes **including every joining newline**; fail with generic evidence-integrity `ValueError` before constructing/returning a report above the limit.
- Do not emit a partial return. Do not mutate supplied findings, evidence or metadata, do not coerce/normalize evidence, and leave the existing empty report fallback unchanged.
- This does **not** prevent transient allocation of the already constructed escaped line values, and is **not a complete memory-DoS bound**. It also does not sanitize secrets, grant access, verify evidence or render actual Markdown to HTML. Final limit and legacy UX compatibility need source-owner review.
- Earlier W42 Unicode-grapheme and W43 duplicate-lineage controls remain active on this stacked opt-in branch.

`tests/test_finding_markdown_rendered_size_w44.py` adds **five** synthetic unittest methods covering normal escaped batches, adversarial quote→HTML entity expansion with raw input under the admitted 1 MiB but expanded output over 2 MiB, caller-data immutability after rejection, fallback compatibility and correct UTF-8 handling for accented/emoji references.

Exact-head test commands:
```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_markdown_rendered_size_w44.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

No actual target interaction, evidence collection, authorizing decision, executed remediation/retest, merge or deploy. Exact-head hosted diagnostic is not registered permanent self-hosted VPS release CI. Original #894/#100/#732 source-owner review, downstream real Markdown renderer/privacy tests, historical compatibility, latest-main composition, independent security review and explicit release approval remain mandatory.