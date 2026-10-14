# Offline registry CLI no-write / no-SQLite regressions (#1362)

LightUp remains **INCUBATE M3/M7 · PLAN/LAB ONLY**. The eight
source-local export and registry review entrypoints promise read-only
developer metadata checks. Existing hermetic tests guard Python socket/DNS
attempts; this independent synthetic test suite additionally proves that
their **actual CLI paths** do not try filesystem or SQLite state mutation.

The regression opens a disposable Python process with pre-import hooks
for write-capable `open`, `os.open`, `Path.open/write_*/mkdir/unlink`,
`os.mkdir/rename/replace/remove`, and `sqlite3.connect`. The hooks
print an explicit denial marker even when the program catches an
exception. Test fixtures are created **only by the parent outside the
hooked subprocess**. Python bytecode generation is disabled for the
child, so ordinary import cache writes do not obscure validation.

The 16 methods exercise genuine exporter, pairwise comparison,
multi-version history, history versus checkout, Markdown report,
incubation posture, closed-world catalog and semantic field-review CLIs, with unchanged,
modified/reverted, malformed/absent and hostile arguments. Valid
catalog controls remain `REVIEW_ONLY` with exit **3**; invalid or
drifted inputs **HOLD** with exit **2**, never 0. JSON receipts have
all five explicit false authorization/permit/execution/merge/release
flags; Markdown always declares **Authority: NONE**.

Run locally in a checkout:

```bash
python3 -m unittest discover -s tests -p 'test_scope_offline_registry_no_write_20261014.py' -v
```

This is **Python-level instrumentation, not an OS sandbox** or
tamper-proof proof against native extensions, malicious import-time
behavior before instrumentation, independent signed source attestations
or a write that was already performed before the test. OS egress and
filesystem isolation, tenant consent/ownership, grants, live revocation,
real target authority and deployment need independent controls.

New tests/docs only, no production executor, scope policy, grant,
state-store, runner, workflow or concurrently owned source path edits.
