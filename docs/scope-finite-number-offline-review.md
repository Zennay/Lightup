# Offline finite NUMBER admission reference — #1143

**State:** INCUBATE M3/M7 / PLAN-LAB ONLY. Non-authorizing, opt-in, not registered with production `ToolExecutor`. No active target, network, grant, scan, deployment, or release decision.

`src/lightup/finite_number_offline_review.py` implements a strict, atomic immutable snapshot for a bounded list of named numeric arguments. Reject NaN / positive and negative infinity, bool, `IntEnum`, user-defined numeric subclasses, duplicate/invalid field names, non-tuple containers, partial batches and oversized inputs. Exact built-in finite `int` and `float` are supported, including arbitrarily large finite Python ints without float coercion. The returned sorted tuple can be passed by an **explicit** synthetic call site only. The minimal receipt never includes input values or untrusted names and hardcodes all authority and deployment fields false.

`tests/test_scope_finite_number_offline_review.py` verifies real offline pre-admission with original `ToolExecutor` and disposable SQLite/evidence side effects; invalid late arguments must be refused before a caller invokes that executor. This does **not** fix original `ParamKind.NUMBER.accepts`, which currently accepts non-finite floats, nor original type-identity admission #1095. Standalone previews are not a security boundary unless the production source owner integrates mandatory admission before handlers. No claims of real authorized scan protection.

**Next source-owner integration** (not part of this branch): #156 / #107 owner must implement exact finite numeric validation inside the canonical production parameter validation path and convert genuine original-source RED tests to ordinary PASS without weakening risk/consent/scope/revocation controls. Independent security/privacy review, exact-head hosted Python3.11/3.14 and permanent runner validation, and deployment permission remain separate.

This branch intentionally creates only three new self-owned paths; no existing source, other worker PR, workflow, runner or deployment file is changed.
