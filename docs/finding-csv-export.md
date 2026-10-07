# Finding summary CSV export

`lightup.finding_export.render_findings_csv(findings)` returns a CSV string
from an already-authorized list of `Finding` objects. It performs no network,
database, filesystem or model calls and does not change any finding.

Columns are fixed: finding_id, title, severity, retest_status, remediation.
Input order is preserved. Empty input returns only the header. Fields are
always quoted and embedded quotes/newlines use standard CSV escaping.

Targets, raw evidence, and arbitrary metadata are omitted. Known credential
patterns pass through the existing shared redactor. This is not exhaustive
secret detection: operators must review free text before external sharing.
The exporter does not independently prove tenant ownership; callers must
select findings through the authorized domain read boundary. No CLI or web
route is added by this package.

Formula-like fields beginning with =, +, -, or @ after whitespace/control
characters receive a leading apostrophe. Leading tab/CR/LF fields also receive
that prefix. Unicode whitespace and ASCII controls are considered when
checking the formula prefix. This changes presentation text intentionally;
CSV consumers should preserve the prefix. Spreadsheet import behavior varies,
so stripping presentation guards or re-saving with another program is outside
this contract.

Invalid required text, noncanonical enums, non-Finding entries and duplicate
finding IDs fail before a string is returned. Rejection is read-only.
No empty report is a clean bill of health, and exported severity/retest values
are existing claims, not a newly evaluated verdict.

## Integration and verification

Use the helper only after an authorized finding selection:

```python
from lightup.finding_export import render_findings_csv
csv_text = render_findings_csv(authorized_findings)
```

Focused verification uses `python -m unittest discover -s tests -p test_finding_export.py -v`
with `PYTHONPATH=src` on the canonical runner. Standard PR CI also runs the full
suite. Keep the PR draft until exact-head permanent VPS proof is green.

This package owns only its new module, test and document. It does not modify
the active Markdown reporting, redaction, domain, scope, authorization or
evidence-remediation branches.
