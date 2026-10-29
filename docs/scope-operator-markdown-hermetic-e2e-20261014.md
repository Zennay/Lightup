# Hermetic operator Markdown CLI no-effect acceptance (#1374)

The new `render_scope_incubation_dossier_offline.py` entrypoint
prints a safe human-readable three-gate capability-review receipt.
This regression suite proves that, for actual source mutations, the
**installed Markdown CLI** remains a read-only, non-authorizing tool
just like its machine-readable JSON counterpart.

```bash
python3 -m unittest discover -s tests -p 'test_scope_operator_markdown_hermetic_e2e_20261014.py' -v
```

**14 tests**, each spawning an isolated Python interpreter with
pre-import hooks that print a distinctive attempt marker and refuse:

- DNS/socket/connect/send operations;
- write-capable builtin and OS `open`, `Path.write*`, `os.*`
  filesystem mutations;
- `sqlite3.connect` or creation of another process.

Fixtures change only an in-memory copy of `get_capabilities()`
inside each disposable subprocess. Scenarios: unchanged source,
name/description/both metadata, ordinary/lab state changes,
explicit activation disabled, added/missing capabilities, malformed
registry containers/noncanonical text, script-like descriptions,
target/execute CLI arguments and combinations.

All valid reviewed metadata exits **3 REVIEW_ONLY**, and drift,
unknown metadata or malformed input exits **2 HOLD**. No invocation
may return success/0. The Markdown document always says
**Authority: NONE.** and explicitly denies grant, target execution,
real scan, merge, release or production deployment. The original
untrusted name/description/HTML/target text never appears in output;
only canonical ID and fixed violation labels can appear. Invalid
metadata produces no partial fingerprint.

These are **Python-level regression hooks**, not an OS-enforced
egress/filesystem sandbox, signed provenance or proof of live
authorization. A malicious native operation bypassing the Python
intercept is out of scope. No real target, socket, customer/grant
state, filesystem output file, VPS mutation, active scan or
production deployment is performed.

This PR consists of **two new test/docs paths only**. Production
authorization, execution, StateStore, WebSecurity, CI, runner,
other parallel workers and the already merged report implementation
are untouched. Source merge requires exact-head hosted Python3.11/3.14
unittests and genuine producer integrations passing.
