# #1023 synthetic intake inventory and parser-allocation ordering

**Status:** LightUp Incubate M3/M7, PLAN/LAB ONLY. Evidence is for design review, **not production authorization**. Review at exact default-main source tree `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`; do not assume this inspection covers newer unpublished owner branches.

## Source-level intake inventory (inspection, not installed-ingress proof)

| Path | Current input contract | Relationship to proposed authorization JSON envelope |
| --- | --- | --- |
| `src/lightup/webapp/app.py:LightUpWebApp.__call__` | Calls `WebSecurity.validate`, then `read_form` for POST, then authenticates session and dispatches registered routes; grants route uses HTML POST | Existing WSGI app is **form-only**, no generic JSON authorization-envelope intake established. Replacing the form parser is *not* authorized by #1023. |
| `src/lightup/webapp/forms.py:read_form` | Rejects unsafe framing, fixed-length >64 KiB, wrong content type, malformed UTF-8, duplicate security-sensitive form fields | Separate owned form boundary. Do **not** route raw JSON through this without a deliberate API design/review. |
| `src/lightup/ai/planner.py:parse_plan` | `json.loads(raw: str)` on model-proposed plans, then catalog/scenario validation | JSON is a **plan**, not a client/issuer-signed authorization envelope. Separate lab/model planner admission owner; do not claim #1012 protects it. |
| `src/lightup/ai/orchestration.py:ToolExecutor.execute` | Receives typed `ToolCall` and `RunContext`; policy evaluates after argument validation | No raw JSON authorization envelope. Must not trust a newly parsed envelope as authority; evaluate actual persisted grant and STOP separately. |
| `src/lightup/domain.py:record_authorization_grant` and `_grant_from_row` | Operator-controlled typed issuance; serialized JSON arrays for persisted scope and later `json.loads` reconstruction | **Durable scope schema** belongs to other issue owners (#554/#639/#877 et al.), not the raw request-envelope parser. Do not conflate origin and tenant truth with syntactic JSON shape. |
| `src/lightup/cli.py` | `argparse` commands and flags, JSON output for scope/plan reporting | No observed JSON authorization-envelope intake. |

**Conclusion:** #1023 requires product/source-owner identification of a concrete future raw-envelope intake. Until such an intake exists, wiring #1012 into current form routes, grant issuance, model planning or executors would be unreviewed scope expansion. The gate cannot simply be enabled as a security fix.

## Two intentional failing acceptance canaries

The standalone `tests/test_scope_1023_preparse_resource_gap_20261012.py` adds **two deliberate `@expectedFailure` negative canaries** against the #1012 uninstalled reference:

1. `max_depth` on a nested JSON object currently rejects **only after `json.loads` is invoked**.
2. `max_nodes` on a nested array similarly rejects **after full JSON decoding**.

Additional green controls independently establish that bytes/type/budget and malformed UTF-8 are rejected **before** invoking `json.loads`; shape-only acceptance and normal postparse depth/node denials remain separate. These expected RED results do **not** prove an exploit, a hard RSS/peak allocation bound, or a live authorization bypass. They characterize what the reference does not guarantee.

## Required source-owner implementation

- Define a concrete, threat-modeled raw-envelope endpoint and exact byte/depth/node budgets. Budget decisions must be reviewed for legitimate traffic, not copied from illustrative defaults.
- If preparse depth/node memory control is required, enforce it before full-tree materialization, or use a bounded streaming/iterative parser with independently tested memory properties; reject duplicate object keys, invalid encodings, nonfinite numbers and malformed trees atomically.
- Keep shape parsing orthogonal to persisted issuer, tenant, engagement, asset, capability, risk, approval, clock, STOP/revocation and signed human consent. Denial must occur before queue, database authorization mutation, handler, or network operation.
- Convert the two deliberate expected failures to ordinary passing tests **only when a real chosen production intake demonstrably has the property**. Do not delete/skip a failing security expectation merely to turn CI green.
- Ownership: PR #107 for execution/admission, #1012 for the original uninstalled envelope reference, #1002 for JSON-duplicate semantics, and the appropriate WSGI/DomainStore owner for any future ingress. No cross-worker source edits here.
- Release gate: exact-head hosted Python 3.11/3.14 and separately registered permanent VPS CI, realistic offline integration including tenants and revocation, independent security/privacy review, latest-main composition, and explicit human approval.

**No active targets, scans, new grants, production routing, deployment, merges or external HTTP.** Keep [issue #1023](https://github.com/Zennay/Lightup/issues/1023) and [DRAFT #1264](https://github.com/Zennay/Lightup/pull/1264) in HOLD.
